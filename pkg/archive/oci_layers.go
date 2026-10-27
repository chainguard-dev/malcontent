// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/chainguard-dev/clog"
)

// ociSkipWarning starts the warning logged for each layer entry that cannot be
// applied. The entry is skipped and the rest of the image is still extracted.
const ociSkipWarning = "skipping image entry"

const (
	ociWhiteoutPrefix = ".wh."
	ociOpaqueMarker   = ".wh..wh..opq"
	// maxOCISymlinkHops bounds symlink resolution as continuity's fs.RootPath
	// bounds it.
	maxOCISymlinkHops = 255
)

type ociKind uint8

const (
	ociDir ociKind = iota
	ociRegular
	ociSymlink
	ociSpecial // a device or FIFO: it occupies its path but is not created
)

// ociNode is one path of the image filesystem being assembled. Directories
// and regular files also exist on disk at the same path. Symlinks exist only
// here until finish creates them, so no disk operation ever follows one.
type ociNode struct {
	kind ociKind
	// layer is the last layer that wrote this path or, for a directory, an
	// entry below it. Whiteouts remove only what lower layers wrote.
	layer    int
	target   string // symlink target as the layer recorded it
	children map[string]*ociNode
}

func newOCIDir(layer int) *ociNode {
	return &ociNode{kind: ociDir, layer: layer, children: map[string]*ociNode{}}
}

// ociSkipError reports an entry that cannot be applied. It does not stop the
// extraction.
type ociSkipError struct{ reason string }

func (e *ociSkipError) Error() string { return e.reason }

func skipEntry(format string, args ...any) error {
	return &ociSkipError{reason: fmt.Sprintf(format, args...)}
}

// ociTree applies image layers, lowest first, to the directory of root and
// leaves there the filesystem containerd runs. It follows containerd's
// applyNaive (containerd/containerd pkg/archive/tar.go at de4c2a3): names are
// cleaned and rooted, so a leading "/" or ".." cannot leave the image; parent
// directories resolve through symlinks already applied, as fs.RootPath does
// (containerd/continuity fs/path.go at 555e512), and are created when
// missing; an entry replaces whatever is at its path unless both are
// directories; and a hardlink's target resolves the same way. Where containerd
// removes whatever a whiteout names, the tree removes only what lower layers
// wrote, as the OCI image spec requires, so its own layer's entries stay in
// either order. A hardlink shares its target's file, so it keeps the bytes
// when an upper layer deletes or replaces the target, as overlay copy-up does.
type ociTree struct {
	root   *os.Root
	top    *ociNode
	layer  int
	buf    []byte
	logger *clog.Logger
}

func newOCITree(root *os.Root, buf []byte, logger *clog.Logger) *ociTree {
	return &ociTree{root: root, top: newOCIDir(0), buf: buf, logger: logger}
}

// applyLayer applies the tar stream r as layer n, which must be higher than
// every layer applied before it. It reads r to its end so that a verifying
// blob reader checks the layer's digest.
func (t *ociTree) applyLayer(ctx context.Context, n int, r io.Reader) error {
	t.layer = n
	tr := tar.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read layer %d: %w", n, err)
		}
		if err := t.apply(hdr, tr); err != nil {
			skip, ok := errors.AsType[*ociSkipError](err)
			if !ok {
				return fmt.Errorf("apply %q from layer %d: %w", hdr.Name, n, err)
			}
			t.logger.Warnf("%s %q from layer %d: %s", ociSkipWarning, hdr.Name, n, skip.reason)
		}
	}
	if _, err := io.CopyBuffer(io.Discard, r, t.buf); err != nil {
		return fmt.Errorf("verify layer %d: %w", n, err)
	}
	return nil
}

// apply applies one entry, reading a regular file's contents from data.
func (t *ociTree) apply(hdr *tar.Header, data io.Reader) error {
	if hdr.Typeflag == tar.TypeXGlobalHeader {
		return nil
	}
	name := ociRootedName(hdr.Name)
	if name == "" {
		return nil // the root itself, which containerd also passes over
	}
	dir, base := path.Split(name)
	if base == ociOpaqueMarker {
		return t.opaque(dir)
	}
	if orig, ok := strings.CutPrefix(base, ociWhiteoutPrefix); ok {
		return t.whiteout(dir, orig)
	}
	comps, err := t.resolve(dir)
	if err != nil {
		return err
	}
	parent, at, err := t.mkparent(comps)
	if err != nil {
		return err
	}
	switch hdr.Typeflag {
	case tar.TypeDir:
		return t.mkdir(parent, at, base)
	case tar.TypeSymlink:
		if hdr.Linkname == "" {
			return skipEntry("symlink has no target")
		}
		if err := t.remove(parent, at, base); err != nil {
			return err
		}
		parent.children[base] = &ociNode{kind: ociSymlink, layer: t.layer, target: hdr.Linkname}
		return nil
	case tar.TypeLink:
		return t.hardlink(parent, at, base, hdr.Linkname)
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		if err := t.remove(parent, at, base); err != nil {
			return err
		}
		parent.children[base] = &ociNode{kind: ociSpecial, layer: t.layer}
		return skipEntry("device and FIFO entries are not extracted")
	case tar.TypeReg, tar.TypeCont, tar.TypeGNUSparse:
		return t.file(parent, at, base, data)
	default:
		// containerd rejects unknown types; keep any data so that it is scanned.
		if hdr.Size > 0 {
			return t.file(parent, at, base, data)
		}
		return skipEntry("unsupported entry type %q", hdr.Typeflag)
	}
}

// ociRootedName returns name relative to the image root. Like containerd's
// filepath.Clean and fs.RootPath, it drops leading slashes and stops ".." at
// the root. Backslashes and drive letters are ordinary name characters.
func ociRootedName(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

// ociJoin joins a canonical directory path and a name.
func ociJoin(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// resolve follows p from the root through symlinks in every component, as
// fs.RootPath does: an absolute target restarts at the root, ".." stops there,
// and too many links is an error. It returns the canonical components, which
// cross no symlink; the trailing ones may not exist yet.
func (t *ociTree) resolve(p string) ([]string, error) {
	var comps []string
	var nodes []*ociNode // nodes[i] is the node at comps[:i+1], nil if missing
	pending := strings.Split(p, "/")
	hops := 0
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(comps) > 0 {
				comps, nodes = comps[:len(comps)-1], nodes[:len(nodes)-1]
			}
			continue
		}
		parent := t.top
		if len(nodes) > 0 {
			parent = nodes[len(nodes)-1]
		}
		var n *ociNode
		if parent != nil {
			n = parent.children[c]
		}
		if n == nil || n.kind != ociSymlink {
			comps, nodes = append(comps, c), append(nodes, n)
			continue
		}
		if hops++; hops > maxOCISymlinkHops {
			return nil, skipEntry("too many levels of symbolic links")
		}
		if path.IsAbs(n.target) {
			comps, nodes = comps[:0], nodes[:0]
		}
		pending = append(strings.Split(n.target, "/"), pending...)
	}
	return comps, nil
}

// lookup returns the node at the canonical comps and its path, or nil if it
// does not exist.
func (t *ociTree) lookup(comps []string) (*ociNode, string) {
	n := t.top
	for _, c := range comps {
		if n = n.children[c]; n == nil {
			return nil, ""
		}
	}
	return n, strings.Join(comps, "/")
}

// mkparent returns the directory at the canonical comps and its path,
// creating the directories that are missing. Every directory on the way is
// marked as written by the current layer.
func (t *ociTree) mkparent(comps []string) (*ociNode, string, error) {
	n := t.top
	for i, c := range comps {
		child := n.children[c]
		switch {
		case child == nil:
			if err := t.root.Mkdir(filepath.FromSlash(strings.Join(comps[:i+1], "/")), 0o700); err != nil {
				return nil, "", diskErr(err)
			}
			child = newOCIDir(t.layer)
			n.children[c] = child
		case child.kind == ociDir:
			child.layer = t.layer
		default:
			return nil, "", skipEntry("%s is not a directory", strings.Join(comps[:i+1], "/"))
		}
		n = child
	}
	return n, strings.Join(comps, "/"), nil
}

// diskErr turns an error the filesystem raised about one entry's name, such as
// a name too long or a collision on a case-insensitive filesystem, into a
// skip. Other errors, such as a full disk, stop the extraction.
func diskErr(err error) error {
	nameErrs := []error{fs.ErrExist, syscall.ENAMETOOLONG, syscall.EILSEQ, syscall.EINVAL, syscall.ENOTDIR, syscall.EISDIR}
	if slices.ContainsFunc(nameErrs, func(e error) bool { return errors.Is(err, e) }) {
		return skipEntry("%v", err)
	}
	return err
}

// remove deletes the entry named base in parent, at canonical path at, from
// the tree and the disk.
func (t *ociTree) remove(parent *ociNode, at, base string) error {
	n := parent.children[base]
	if n == nil {
		return nil
	}
	delete(parent.children, base)
	p := filepath.FromSlash(ociJoin(at, base))
	var err error
	switch n.kind {
	case ociDir:
		err = t.root.RemoveAll(p)
	case ociRegular:
		err = t.root.Remove(p)
	case ociSymlink, ociSpecial:
		// These exist only in the tree.
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// hideLower removes what lower layers wrote at or below the entry named base
// in parent, keeping what the current layer wrote.
func (t *ociTree) hideLower(parent *ociNode, at, base string) error {
	n := parent.children[base]
	switch {
	case n == nil:
		return nil
	case n.layer < t.layer:
		return t.remove(parent, at, base)
	case n.kind != ociDir:
		return nil
	}
	p := ociJoin(at, base)
	for name := range n.children {
		if err := t.hideLower(n, p, name); err != nil {
			return err
		}
	}
	return nil
}

// opaque applies an opaque-directory marker in dir: what lower layers wrote
// below dir is hidden.
func (t *ociTree) opaque(dir string) error {
	comps, err := t.resolve(dir)
	if err != nil {
		return err
	}
	n, at := t.lookup(comps)
	if n == nil || n.kind != ociDir {
		return nil
	}
	for name := range n.children {
		if err := t.hideLower(n, at, name); err != nil {
			return err
		}
	}
	return nil
}

// whiteout applies a whiteout for orig in dir.
func (t *ociTree) whiteout(dir, orig string) error {
	if orig == "" || orig == "." || orig == ".." {
		return skipEntry("whiteout names no entry")
	}
	comps, err := t.resolve(dir)
	if err != nil {
		return err
	}
	parent, at := t.lookup(comps)
	if parent == nil || parent.kind != ociDir {
		return nil
	}
	return t.hideLower(parent, at, orig)
}

// mkdir creates the directory base in parent, merging with a directory
// already there.
func (t *ociTree) mkdir(parent *ociNode, at, base string) error {
	if n := parent.children[base]; n != nil && n.kind == ociDir {
		n.layer = t.layer
		return nil
	}
	if err := t.remove(parent, at, base); err != nil {
		return err
	}
	if err := t.root.Mkdir(filepath.FromSlash(ociJoin(at, base)), 0o700); err != nil {
		return diskErr(err)
	}
	parent.children[base] = newOCIDir(t.layer)
	return nil
}

// file writes the regular file base in parent from data.
func (t *ociTree) file(parent *ociNode, at, base string, data io.Reader) error {
	if err := t.remove(parent, at, base); err != nil {
		return err
	}
	f, err := t.root.OpenFile(filepath.FromSlash(ociJoin(at, base)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return diskErr(err)
	}
	parent.children[base] = &ociNode{kind: ociRegular, layer: t.layer}
	// Hiding the file's ReaderFrom keeps the copy on the pooled buffer.
	_, err = io.CopyBuffer(struct{ io.Writer }{f}, data, t.buf)
	return errors.Join(err, f.Close())
}

// hardlink links base in parent to linkname, resolved as containerd's
// hardlinkRootPath resolves it: through symlinks in its parent directories but
// not in its last component.
func (t *ociTree) hardlink(parent *ociNode, at, base, linkname string) error {
	target := ociRootedName(linkname)
	if target == "" {
		return skipEntry("hardlink target is the image root")
	}
	tdir, tbase := path.Split(target)
	comps, err := t.resolve(tdir)
	if err != nil {
		return err
	}
	var src *ociNode
	tparent, tat := t.lookup(comps)
	if tparent != nil {
		src = tparent.children[tbase]
	}
	switch {
	case src == nil:
		return skipEntry("hardlink target %q does not exist", linkname)
	case src.kind == ociDir:
		return skipEntry("hardlink target %q is a directory", linkname)
	}
	from, to := ociJoin(tat, tbase), ociJoin(at, base)
	switch {
	case from == to:
		return nil
	case strings.HasPrefix(from, to+"/"):
		return skipEntry("hardlink would replace a directory holding its target %q", linkname)
	}
	if err := t.remove(parent, at, base); err != nil {
		return err
	}
	switch src.kind {
	case ociSymlink:
		// A hardlink to a symlink is a second symlink with the same target.
		parent.children[base] = &ociNode{kind: ociSymlink, layer: t.layer, target: src.target}
		return nil
	case ociSpecial:
		parent.children[base] = &ociNode{kind: ociSpecial, layer: t.layer}
		return skipEntry("device and FIFO entries are not extracted")
	case ociDir, ociRegular:
		// A directory target was rejected above; a regular file is linked below.
	}
	if err := t.root.Link(filepath.FromSlash(from), filepath.FromSlash(to)); err != nil {
		return diskErr(err)
	}
	parent.children[base] = &ociNode{kind: ociRegular, layer: t.layer}
	return nil
}

// finish creates the image's symlinks once every layer is applied. Each
// points at its target's place in the tree by a relative path, so no link
// leads out of the extraction directory. A symlink whose target cannot be
// resolved is skipped.
func (t *ociTree) finish() error {
	return t.finishDir(t.top, "")
}

func (t *ociTree) finishDir(n *ociNode, at string) error {
	for _, name := range slices.Sorted(maps.Keys(n.children)) {
		child := n.children[name]
		p := ociJoin(at, name)
		var err error
		switch child.kind {
		case ociDir:
			err = t.finishDir(child, p)
		case ociSymlink:
			err = t.symlink(at, p, child.target)
		case ociRegular, ociSpecial:
			// Regular files are already on disk; special files are never created.
		}
		if skip, ok := errors.AsType[*ociSkipError](err); ok {
			t.logger.Warnf("%s %q: %s", ociSkipWarning, p, skip.reason)
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// symlink creates the symlink at canonical path p, in directory dir, that
// leads where target leads in the image.
func (t *ociTree) symlink(dir, p, target string) error {
	from := target
	if !path.IsAbs(target) {
		from = ociJoin(dir, target)
	}
	comps, err := t.resolve(from)
	if err != nil {
		return err
	}
	rel := ociRelative(strings.Split(dir, "/"), comps)
	if err := t.root.Symlink(filepath.FromSlash(rel), filepath.FromSlash(p)); err != nil {
		return diskErr(err)
	}
	return nil
}

// ociRelative returns the relative path from directory from to to, both
// canonical components.
func ociRelative(from, to []string) string {
	from = slices.DeleteFunc(from, func(c string) bool { return c == "" })
	common := 0
	for common < min(len(from), len(to)) && from[common] == to[common] {
		common++
	}
	parts := slices.Concat(slices.Repeat([]string{".."}, len(from)-common), to[common:])
	if len(parts) == 0 {
		return "."
	}
	return strings.Join(parts, "/")
}
