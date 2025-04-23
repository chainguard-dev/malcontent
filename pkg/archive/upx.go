package archive

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

func ExtractUPX(ctx context.Context, d, f string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Check if UPX is installed
	if err := programkind.UPXInstalled(); err != nil {
		return err
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting upx")

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	gf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer gf.Close()

	target := filepath.Join(d, filepath.Base(f))
	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid file path: %s", target)
	}

	tf, err := os.ReadFile(f)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	err = os.WriteFile(target, tf, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	cmd := exec.Command("upx", "-d", "-k", target)
	output, err := cmd.CombinedOutput()
	if err != nil {
		os.Remove(target)
		return fmt.Errorf("failed to decompress upx file: %w, output: %s", err, output)
	}

	if !strings.Contains(string(output), "Decompressed") && !strings.Contains(string(output), "Unpacked") {
		os.Remove(target)
		return fmt.Errorf("upx decompression might have failed: %s", output)
	}

	logger.Debug("successfully decompressed upx file", "output", string(output), "target", target)
	return nil
}
