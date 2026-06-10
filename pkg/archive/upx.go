// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

const (
	upxTimeout   = 30 * time.Second
	upxOutputCap = 1 << 20 // 1 MiB ceiling on captured stdout/stderr.
	upxWaitDelay = 5 * time.Second
)

// buildUPXCmd returns a fully configured *exec.Cmd. The caller is responsible
// for invoking cmd.Run() and for cleaning up tmpdir. Stdout/Stderr are left
// unset so callers can attach bounded buffers.
func buildUPXCmd(ctx context.Context, upxPath, tmpdir, target string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, upxPath, "-d", "-k", "--", target) // #nosec G204 -- invokes pinned upx binary with validated path arg
	cmd.Env = []string{"PATH=/usr/bin", "LANG=C"}
	cmd.Stdin = nil
	cmd.Dir = tmpdir
	cmd.WaitDelay = upxWaitDelay
	applySysProcAttr(cmd)
	return cmd
}

// boundedBuffer caps the bytes retained while still acknowledging the full
// write. Callers receive the same n the underlying writer would, but content
// past cap is silently dropped to bound memory.
type boundedBuffer struct {
	bytes.Buffer
	cap int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len() >= b.cap {
		return len(p), nil
	}
	room := b.cap - b.Len()
	if len(p) > room {
		if _, err := b.Buffer.Write(p[:room]); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// copyBoundedToSandbox copies up to limit bytes from src into dst. Returns
// the number of bytes written and the first error from the underlying Copy.
// The LimitReader wrapper is what enforces the byte cap -- without it, a
// pathologically large input would drive sandbox disk usage to OOM.
func copyBoundedToSandbox(dst io.Writer, src io.Reader, limit int64) (int64, error) {
	if limit <= 0 {
		return 0, errors.New("copyBoundedToSandbox: limit must be positive")
	}
	return io.Copy(dst, io.LimitReader(src, limit))
}

func ExtractUPX(ctx context.Context, d, f string) (err error) {
	defer recoverExtractor(ctx, "upx", f, &err)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	upxPath, err := programkind.UPXInstalled()
	if err != nil {
		return err
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting upx")

	if _, err := os.Stat(f); err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	base := filepath.Base(f)
	if strings.HasPrefix(base, "-") {
		return fmt.Errorf("file name begins with '-': %q", base)
	}
	if len(base) > 255 {
		return fmt.Errorf("file name exceeds 255 characters")
	}

	target := filepath.Join(d, filepath.Base(f))
	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid file path: %s", target)
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	src, err := os.Open(f) // #nosec G304 -- source path resolved and validated by caller before extraction
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = src.Close() }()

	// Honor operator-configured archive caps: resolve the effective max-bytes
	// from the context so UPX output is subject to the same per-level budget
	// as every other extractor.
	copyLimit, _ := resolveArchiveCaps(ctx)

	dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- target derived from absTarget computed under sandbox dir
	if err != nil {
		return fmt.Errorf("failed to open target: %w", err)
	}
	if _, err := copyBoundedToSandbox(dst, src, copyLimit); err != nil {
		_ = dst.Close()
		return fmt.Errorf("failed to write file: %w", err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("failed to close target: %w", err)
	}

	// Per-call sandbox dir is UPX's cwd, so it bounds only side files UPX
	// names relatively; absolutely-named outputs (such as the -k backup
	// alongside the absolute target) land in the destination dir, which is
	// itself scanned and cleaned. RemoveAll lets the kernel reclaim the
	// sandbox immediately on completion.
	sandbox, err := os.MkdirTemp("", "mal-upx-*")
	if err != nil {
		return fmt.Errorf("upx sandbox tmpdir: %w", err)
	}
	defer func() { _ = os.RemoveAll(sandbox) }()

	cctx, cancel := context.WithTimeout(ctx, upxTimeout)
	defer cancel()

	cmd := buildUPXCmd(cctx, upxPath, sandbox, absTarget)
	out := &boundedBuffer{cap: upxOutputCap}
	errBuf := &boundedBuffer{cap: upxOutputCap}
	cmd.Stdout = out
	cmd.Stderr = errBuf

	if err := cmd.Run(); err != nil {
		_ = os.Remove(absTarget)
		return fmt.Errorf("failed to decompress upx file: %w (stderr: %q)", err, errBuf.String())
	}

	combined := out.String() + errBuf.String()
	if !strings.Contains(combined, "Decompressed") && !strings.Contains(combined, "Unpacked") {
		_ = os.Remove(absTarget)
		return fmt.Errorf("upx decompression might have failed")
	}

	logger.Debug("successfully decompressed upx file", "output", combined, "target", absTarget)
	return nil
}
