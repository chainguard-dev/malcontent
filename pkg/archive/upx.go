package archive

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

func ExtractUPX(ctx context.Context, d, f string) error {
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

	base := filepath.Base(f)
	target := filepath.Join(d, base[:len(base)-len(filepath.Ext(base))])

	// copy the file to the temporary directory before decompressing
	tf, err := os.ReadFile(f)
	if err != nil {
		return err
	}

	err = os.WriteFile(target, tf, 0o600)
	if err != nil {
		return err
	}

	cmd := exec.Command("upx", "-d", target)
	if _, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to decompress upx file: %w", err)
	}

	return nil
}
