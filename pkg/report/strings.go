// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"cmp"
	"slices"
	"sync"
	"sync/atomic"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/puzpuzpuz/xsync/v4"
)

// maxInternedStrings bounds the number of distinct strings the
// process-wide pool retains. The pool is shared across every match
// processor for the lifetime of the process, so without a cap the
// intern map accumulates every distinct matched string indefinitely.
// When the map reaches this size, Intern resets it; already-returned
// strings stay valid because callers hold their own references and a
// subsequent Intern of the same value simply re-stores it.
const maxInternedStrings = 1 << 16

// maxPooledResultCap is the capacity ceiling for slices returned to
// matchResultPool. Slices that grew beyond this threshold during a
// single file's match processing are dropped to GC instead of pooled,
// preventing one outlier file from parking an oversized backing array.
const maxPooledResultCap = 1024

// StringPool holds data to handle string interning.
//
// The count field is an approximate entry counter maintained via atomic
// increments; it may slightly overcount under concurrent stores of the
// same key but never undercounts a new-key store. The clearing field
// gates resets so that exactly one goroutine performs the Clear when the
// approximate count reaches the cap.
type StringPool struct {
	strings  *xsync.Map[string, string]
	count    atomic.Int64
	clearing atomic.Bool
}

// clear is a no-op for in-package callers. The pool is the process-wide
// singleton, so emptying it on demand would race in-flight Intern calls
// and break the same-backing-array guarantee that concurrent callers
// depend on. Growth is instead bounded inside Intern, which resets the
// pool only once it reaches maxInternedStrings entries.
func (sp *StringPool) clear() {}

// stringPoolSingleton lazily constructs the package-wide pool the
// first time NewStringPool is invoked. sync.OnceValue is lock-free
// after the first call and race-free under concurrent first callers.
var stringPoolSingleton = sync.OnceValue(func() *StringPool {
	return &StringPool{
		strings: xsync.NewMap[string, string](),
	}
})

// NewStringPool returns the process-wide string pool. Successive calls
// return the same instance so interning state is shared across every
// match processor for the lifetime of the process.
func NewStringPool() *StringPool {
	return stringPoolSingleton()
}

// Intern returns an interned version of the input string. An approximate
// atomic counter tracks distinct entries; when it reaches
// maxInternedStrings a single goroutine (selected via CAS) clears the
// map and resets the counter while other goroutines proceed without
// blocking. The count may drift slightly from the true map size under
// heavy concurrency, which is acceptable because the cap is a memory
// bound, not an exact invariant.
func (sp *StringPool) Intern(s string) string {
	interned, loaded := sp.strings.LoadOrStore(s, s)
	if !loaded {
		if sp.count.Add(1) >= maxInternedStrings {
			if sp.clearing.CompareAndSwap(false, true) {
				sp.strings.Clear()
				sp.count.Store(0)
				sp.clearing.Store(false)
			}
		}
	}
	return interned
}

type matchProcessor struct {
	fc       []byte
	pool     *StringPool
	matches  []yarax.Match
	patterns []yarax.Pattern
}

func newMatchProcessor(fc []byte, matches []yarax.Match, mp []yarax.Pattern) *matchProcessor {
	return &matchProcessor{
		fc:       fc,
		pool:     NewStringPool(),
		matches:  matches,
		patterns: mp,
	}
}

var matchResultPool = sync.Pool{
	New: func() any {
		s := make([]string, 0, 32)
		return &s
	},
}

// clearFileContent releases the file content to free memory after processing.
func (mp *matchProcessor) clearFileContent() {
	mp.fc = nil
}

// process performantly handles the conversion of matched data to strings.
// yara-x does not expose the rendered string via the API due to performance overhead.
func (mp *matchProcessor) process() []string {
	if len(mp.matches) == 0 || len(mp.fc) == 0 {
		return nil
	}

	fcl := uint64(len(mp.fc))

	resultPtr, ok := matchResultPool.Get().(*[]string)
	if !ok || resultPtr == nil {
		s := make([]string, 0, len(mp.matches))
		resultPtr = &s
	}
	result := (*resultPtr)[:0]

	for _, match := range mp.matches {
		l := match.Length()
		o := match.Offset()

		if cmp.Or(o > fcl, l > fcl, o+l > fcl) {
			continue
		}

		matchBytes := mp.fc[o : o+l]

		if containsUnprintable(matchBytes) {
			patterns := make([]string, 0, len(mp.patterns))
			for _, p := range mp.patterns {
				if slices.ContainsFunc(p.Matches(), func(m yarax.Match) bool {
					return m.Length() > 0
				}) {
					patterns = append(patterns, mp.pool.Intern(p.Identifier()))
				}
			}
			result = append(result, slices.Compact(patterns)...)
		} else {
			result = append(result, mp.pool.Intern(string(matchBytes)))
		}
	}

	ret := append([]string{}, result...)

	if cap(result) <= maxPooledResultCap {
		*resultPtr = result
		matchResultPool.Put(resultPtr)
	}

	return ret
}

// containsUnprintable determines if a byte is a valid character.
func containsUnprintable(b []byte) bool {
	for _, c := range b {
		if c < 32 || c > 126 {
			return true
		}
	}
	return false
}
