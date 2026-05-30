// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"cmp"
	"slices"
	"sync"

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

// StringPool holds data to handle string interning.
type StringPool struct {
	strings *xsync.Map[string, string]
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

// Intern returns an interned version of the input string. When the pool
// reaches maxInternedStrings distinct entries it is reset before storing,
// bounding the pool's memory footprint over the process lifetime.
func (sp *StringPool) Intern(s string) string {
	if sp.strings.Size() >= maxInternedStrings {
		sp.strings.Clear()
	}
	interned, _ := sp.strings.LoadOrStore(s, s)
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

	*resultPtr = result
	matchResultPool.Put(resultPtr)

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
