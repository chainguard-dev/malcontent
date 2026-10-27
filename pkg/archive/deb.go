// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/egibs/go-debian/deb"
)

// debControlDir is the directory, beneath the extraction directory, that the
// members of a package's control tarball are extracted into: its control
// file, maintainer scripts such as postinst, and the rest.
const debControlDir = "control"

// ExtractDeb extracts .deb packages. It walks the package's ar members in
// order, as dpkg reads them, and extracts every one: the data tarball into
// the extraction directory, the control tarball into control/, and any other
// member as a file of its name. A later data or control tarball, which dpkg
// would not install, is extracted into a sibling directory, data_1 or
// control_1 and so on, so that its content is scanned too.
func ExtractDeb(ctx context.Context, d, f string) (retErr error) {
	defer recoverExtractor(ctx, "deb", f, &retErr)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting deb")

	fd, fi, err := openRegular(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer fd.Close()

	ar, err := deb.LoadAr(newReadAheadReaderAt(fd))
	if err != nil {
		return fmt.Errorf("failed to load file: %w", err)
	}

	// One counter across every member enforces a uniform ratio ceiling;
	// InputBytes seeds the ratio denominator from the deb file size.
	counter := newArchiveCounter(ctx, fi.Size())

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()

	buf := extractPool.Get()
	defer extractPool.Put(buf)
	x := newTarExtraction(ctx, root, counter, buf)
	defer x.close()

	var lost []error
	seen := map[string]int{}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		member, err := ar.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			lost = append(lost, fmt.Errorf("failed to read ar member: %w", err))
			break
		}
		if member.Size < 0 {
			lost = append(lost, fmt.Errorf("ar member %q has a negative size", member.Name))
			break
		}
		if err := counter.Entry(); err != nil {
			return fmt.Errorf("deb extraction aborted on %q: %w", member.Name, err)
		}
		err = extractDebMember(x, member, seen)
		if err == nil {
			continue
		}
		if fatalExtractionError(ctx, err) {
			return err
		}
		logger.Warnf("failed to extract ar member %q: %v", member.Name, err)
		lost = append(lost, fmt.Errorf("ar member %q: %w", member.Name, err))
	}

	err = x.finish(".")
	if len(lost) > 0 {
		err = errors.Join(err, fmt.Errorf("%w: %w", ErrUnaccountedBytes, errors.Join(lost...)))
	}
	return err
}

// extractDebMember extracts one ar member. seen counts the tarballs of each
// role already extracted.
func extractDebMember(x *tarExtraction, member *deb.ArEntry, seen map[string]int) error {
	role, isTar := debMemberRole(member.Name)
	if !isTar {
		return writeDebMember(x, member)
	}
	dir := debMemberDir(role, seen[role])
	seen[role]++
	stream, done, err := debTarStream(x.ctx, member, &x.sc)
	if err != nil {
		return err
	}
	defer done()
	return x.extract(stream, dir, member.Name)
}

// debMemberRole returns what a member named name holds, "control" or "data"
// or the tarball's stem, and whether it is a tarball, named NAME.tar or
// NAME.tar.EXT.
func debMemberRole(name string) (string, bool) {
	stem, rest, found := strings.Cut(name, ".tar")
	if !found || stem == "" || rest != "" && !strings.HasPrefix(rest, ".") {
		return "", false
	}
	return stem, true
}

// debMemberDir returns the directory the nth tarball of role is extracted
// into: control/ for control tarballs and the extraction directory itself for
// data tarballs, and for every later one a sibling directory named after its
// role.
func debMemberDir(role string, n int) string {
	switch {
	case n == 0 && role == "data":
		return "."
	case n == 0 && role == "control":
		return debControlDir
	case n == 0:
		return role
	}
	return role + "_" + strconv.Itoa(n)
}

// debTarStream returns the tar stream in member, decompressed as its content
// shows, or as its name says when the content shows nothing, and the function
// that releases its decoder.
func debTarStream(ctx context.Context, member *deb.ArEntry, sc *sidecar) (io.Reader, func(), error) {
	data := io.NewSectionReader(member.Data, 0, member.Size)
	kind := sniffKind(data, member.Size)
	if kind == kindUnknown && filepath.Ext(member.Name) == ".lzma" {
		r, err := newLZMAReader(data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create lzma reader: %w", err)
		}
		return r, func() {}, nil
	}
	switch kind {
	case kindGzip:
		gz, err := newGzipMembers(data, sc)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		return gz, func() { _ = gz.Close() }, nil
	case kindXZ:
		r, err := newXZReader(data, member.Size)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create xz reader: %w", err)
		}
		return r, func() {}, nil
	case kindBzip2:
		br := newBzip2Reader(ctx, data)
		return br, func() { _ = br.Close() }, nil
	case kindZstd:
		zr, err := newZstdReader(bufferInput(data))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create zstd reader: %w", err)
		}
		return zr, zr.Close, nil
	default:
		return bufferInput(data), func() {}, nil
	}
}

// debBinary is the content of the debian-binary member of every package of
// the current format, which is not written out.
var debBinary = []byte("2.0\n")

// writeDebMember writes a member that is not a tarball as a file of its name.
func writeDebMember(x *tarExtraction, member *deb.ArEntry) error {
	data := io.NewSectionReader(member.Data, 0, member.Size)
	if member.Name == "debian-binary" && member.Size == int64(len(debBinary)) {
		got := make([]byte, len(debBinary))
		if _, err := io.ReadFull(data, got); err == nil && bytes.Equal(got, debBinary) {
			return nil
		}
		data = io.NewSectionReader(member.Data, 0, member.Size)
	}
	name, changed := fileEntryName(member.Name)
	if changed {
		x.logger.Warnf("extracting ar member %q as %q", member.Name, name)
	}
	return handleFile(x.paths, name, data, x.budget)
}
