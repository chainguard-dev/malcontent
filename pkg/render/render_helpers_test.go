// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/fatih/color"
	"github.com/puzpuzpuz/xsync/v4"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// renderNumberedFiles returns a scan report with n files keyed /f/0000
// upward, along with the same reports in a map.
func renderNumberedFiles(n int) (*malcontent.Report, map[string]*malcontent.FileReport) {
	files := xsync.NewMap[string, *malcontent.FileReport]()
	byKey := make(map[string]*malcontent.FileReport, n)
	for i := range n {
		key := fmt.Sprintf("/f/%04d", i)
		fr := &malcontent.FileReport{Path: key, Size: int64(i), RiskScore: i % 5, RiskLevel: riskLevels[i%5]}
		files.Store(key, fr)
		byKey[key] = fr
	}
	return &malcontent.Report{Files: files}, byKey
}

var renderANSIRe = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// errRenderWrite is the error renderWriteLog returns for a failed write.
var errRenderWrite = errors.New("write failed")

// renderWriteLog records each Write call. When failAt is above zero, the
// call with that number fails with errRenderWrite. It is not safe for
// concurrent use.
type renderWriteLog struct {
	writes [][]byte
	failAt int
}

func (w *renderWriteLog) Write(p []byte) (int, error) {
	w.writes = append(w.writes, bytes.Clone(p))
	if len(w.writes) == w.failAt {
		return 0, errRenderWrite
	}
	return len(p), nil
}

// String returns everything written, including a failed write.
func (w *renderWriteLog) String() string {
	return string(bytes.Join(w.writes, nil))
}

// renderStripANSI removes terminal escape sequences so assertions see only visible text.
func renderStripANSI(s string) string {
	return renderANSIRe.ReplaceAllString(s, "")
}

// renderSquash strips escape sequences and collapses whitespace runs, which
// keeps assertions on lipgloss output independent of padding and borders.
func renderSquash(s string) string {
	return strings.Join(strings.Fields(renderStripANSI(s)), " ")
}

// renderRequireNoColor skips tests that compare byte lengths of rendered text,
// because escape sequences count toward those lengths when color is enabled.
func renderRequireNoColor(t *testing.T) {
	t.Helper()
	if !color.NoColor {
		t.Skip("color output is enabled; byte-length assertions need uncolored output")
	}
}

// renderCanceledContext returns a context that is already canceled.
func renderCanceledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}

// renderDiff builds a DiffReport keyed by each report's Path, preserving order.
func renderDiff(removed, added, modified []*malcontent.FileReport) *malcontent.DiffReport {
	d := &malcontent.DiffReport{
		Removed:  orderedmap.New[string, *malcontent.FileReport](),
		Added:    orderedmap.New[string, *malcontent.FileReport](),
		Modified: orderedmap.New[string, *malcontent.FileReport](),
	}
	for _, fr := range removed {
		d.Removed.Set(fr.Path, fr)
	}
	for _, fr := range added {
		d.Added.Set(fr.Path, fr)
	}
	for _, fr := range modified {
		d.Modified.Set(fr.Path, fr)
	}
	return d
}

// renderIndexOrder reports whether every needle appears in s, in the given order.
func renderIndexOrder(s string, needles ...string) bool {
	pos := 0
	for _, n := range needles {
		i := strings.Index(s[pos:], n)
		if i < 0 {
			return false
		}
		pos += i + len(n)
	}
	return true
}
