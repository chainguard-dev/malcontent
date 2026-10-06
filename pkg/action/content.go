// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"sync/atomic"

	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/minio/sha256-simd"
	"github.com/puzpuzpuz/xsync/v4"

	yarax "github.com/VirusTotal/yara-x/go"
)

// sniffed is a file read once, with the kind detected from those bytes, so
// that archive detection, scanning, hashing, and report generation share one
// read.
type sniffed struct {
	fi      fs.FileInfo
	content *file.Contents // nil when the file is empty, not regular, or unreadable
	kind    *programkind.FileType
	err     error // the error programkind.File would return for the file
	// keepSkipped leaves a skipped archive file in place for the caller to
	// remove, rather than removing it as soon as it is skipped.
	keepSkipped bool
}

// sniffFile reads the file at path, whose Stat result is fi, and detects its
// kind as programkind.File does. Empty files are not read, and files that are
// not regular are left to programkind.File.
func sniffFile(ctx context.Context, path string, fi fs.FileInfo) *sniffed {
	s := &sniffed{fi: fi}
	switch {
	case fi.Size() == 0:
		return s
	case !fi.Mode().IsRegular():
		s.kind, s.err = programkind.File(ctx, path)
		return s
	}

	f, err := os.Open(path) // #nosec G304 -- path originates from findFilesRecursively over caller-supplied scan paths or archive temp dirs already validated during extraction
	if err != nil {
		s.err = fmt.Errorf("open: %w", err)
		return s
	}
	s.content, err = file.ReadContents(f, fi.Size())
	_ = f.Close()
	if err != nil {
		s.err = fmt.Errorf("file contents: %w", err)
		return s
	}
	s.kind = programkind.Detect(ctx, path, capContents(s.content.Bytes()))
	return s
}

// close releases the file's contents. It is safe to call on nil.
func (s *sniffed) close() {
	if s != nil {
		_ = s.content.Close()
	}
}

// capContents returns the part of a file's contents that detection, hashing,
// and report generation examine: the first file.MaxBytes.
func capContents(b []byte) []byte {
	return b[:min(int64(len(b)), file.MaxBytes)]
}

// readCapped returns up to file.MaxBytes of the file at path.
func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- see sniffFile
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return file.GetContents(f)
}

// resultCacheBudget bounds the approximate memory, in bytes, that cached scan
// results may hold during one scan.
const resultCacheBudget int64 = 256 << 20

// resultKey identifies scanned content by its SHA-256 digest and length, for
// one rule set.
type resultKey struct {
	rules *yarax.Rules
	sum   [sha256.Size]byte
	size  int64
}

// resultCache holds the yara-x results of content already scanned during one
// scan, so that identical content, such as a module zip and its extracted
// tree, or a library repeated across packages, is scanned once. Results
// depend only on the bytes scanned, and report generation treats them as
// read-only, so one result serves every path with that content.
type resultCache struct {
	m      *xsync.Map[resultKey, *yarax.ScanResults]
	budget atomic.Int64
	// inflight holds the scans in progress, so that a second worker reaching
	// the same content waits for the first scan instead of repeating it.
	inflight *xsync.Map[resultKey, *pendingScan]
}

// pendingScan is a scan in progress; done closes once mrs and err are set.
type pendingScan struct {
	done chan struct{}
	mrs  *yarax.ScanResults
	err  error
}

type resultCacheCtxKey struct{}

// withResultCache returns ctx carrying a new, empty result cache.
func withResultCache(ctx context.Context) context.Context {
	rc := &resultCache{
		m:        xsync.NewMap[resultKey, *yarax.ScanResults](),
		inflight: xsync.NewMap[resultKey, *pendingScan](),
	}
	rc.budget.Store(resultCacheBudget)
	return context.WithValue(ctx, resultCacheCtxKey{}, rc)
}

// resultCacheFrom returns the result cache carried by ctx, or nil.
func resultCacheFrom(ctx context.Context) *resultCache {
	rc, _ := ctx.Value(resultCacheCtxKey{}).(*resultCache)
	return rc
}

// store caches mrs under key while the budget allows.
func (rc *resultCache) store(key resultKey, mrs *yarax.ScanResults) {
	cost := resultCost(mrs)
	if rc.budget.Add(-cost) < 0 {
		rc.budget.Add(cost)
		return
	}
	if _, loaded := rc.m.LoadOrStore(key, mrs); loaded {
		rc.budget.Add(cost)
	}
}

// resultCost estimates the bytes that mrs holds.
func resultCost(mrs *yarax.ScanResults) int64 {
	const entry, rule, pattern, match = 128, 512, 64, 16
	cost := int64(entry)
	for _, r := range mrs.MatchingRules() {
		cost += rule
		for _, p := range r.Patterns() {
			cost += pattern + match*int64(len(p.Matches()))
		}
	}
	return cost
}

// scanContent scans fc, whose capped SHA-256 digest is sum, reusing the
// results of identical content scanned earlier in the same scan, or waiting
// for a scan of it already in progress. Content longer than file.MaxBytes is
// not cached, because sum covers only its start.
func scanContent(ctx context.Context, yrs *yarax.Rules, fc []byte, sum [sha256.Size]byte) (*yarax.ScanResults, error) {
	rc := resultCacheFrom(ctx)
	key := resultKey{rules: yrs, sum: sum, size: int64(len(fc))}
	if key.size > file.MaxBytes {
		// sum covers only the first file.MaxBytes; the rules compare the
		// digest of everything scanned.
		return scanBytes(yrs, fc, sha256.Sum256(fc))
	}
	if rc == nil {
		return scanBytes(yrs, fc, sum)
	}
	if mrs, ok := rc.m.Load(key); ok {
		return mrs, nil
	}

	p := &pendingScan{done: make(chan struct{})}
	if prev, loaded := rc.inflight.LoadOrStore(key, p); loaded {
		select {
		case <-prev.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if prev.err == nil {
			return prev.mrs, nil
		}
		// The scan in progress failed; scanning again reports this file's
		// own error.
		mrs, err := scanBytes(yrs, fc, sum)
		if err == nil {
			rc.store(key, mrs)
		}
		return mrs, err
	}

	p.mrs, p.err = scanBytes(yrs, fc, sum)
	if p.err == nil {
		rc.store(key, p.mrs)
	}
	rc.inflight.Delete(key)
	close(p.done)
	return p.mrs, p.err
}

// scanBytes scans fc, whose SHA-256 digest is sum, with a scanner for yrs.
// It is a variable so that tests can observe how often content is scanned.
var scanBytes = func(yrs *yarax.Rules, fc []byte, sum [sha256.Size]byte) (*yarax.ScanResults, error) {
	return withScanner(yrs, func(s *yarax.Scanner) (*yarax.ScanResults, error) {
		setFileSHA256(s, hex.EncodeToString(sum[:]))
		return s.Scan(fc)
	})
}

// setFileSHA256 sets the digest that rules compare against. A scanner keeps
// globals between scans, so it is set before every scan, empty when the
// digest is unknown. Rule sets compiled without the global ignore it.
func setFileSHA256(s *yarax.Scanner, digest string) {
	_ = s.SetGlobal(compile.FileSHA256, digest)
}

// withScanner runs scan with a scanner for yrs, holding the scanner only for
// the duration of the call.
func withScanner(yrs *yarax.Rules, scan func(*yarax.Scanner) (*yarax.ScanResults, error)) (*yarax.ScanResults, error) {
	if set, ok := scopedSets.Load(yrs); ok {
		return set.with(scan)
	}
	sp := acquireScannerPool(yrs)
	defer sp.release()
	scanner := sp.scanners.Get(yrs)
	defer sp.scanners.Put(scanner)
	return scan(scanner)
}
