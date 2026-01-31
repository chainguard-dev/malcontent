package report

import (
	"slices"
	"sync"

	yarax "github.com/VirusTotal/yara-x/go"
)

// StringPool holds data to handle string interning.
type StringPool struct {
	strings sync.Map
}

// clear removes all strings from the pool to free memory.
func (sp *StringPool) clear() {
	sp.strings.Clear()
}

// NewStringPool creates a new string pool.
func NewStringPool() *StringPool {
	return &StringPool{
		strings: sync.Map{},
	}
}

// Intern returns an interned version of the input string.
func (sp *StringPool) Intern(s string) string {
	interned, _ := sp.strings.LoadOrStore(s, s)
	if is, ok := interned.(string); ok {
		return is
	}
	return s
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
	mp.pool.clear()
}

// process performantly handles the conversion of matched data to strings.
// yara-x does not expose the rendered string via the API due to performance overhead.
func (mp *matchProcessor) process() []string {
	if len(mp.matches) == 0 || len(mp.fc) == 0 {
		return nil
	}

	resultPtr, ok := matchResultPool.Get().(*[]string)
	if !ok || resultPtr == nil {
		s := make([]string, 0, len(mp.matches))
		resultPtr = &s
	}
	result := (*resultPtr)[:0]

	// #nosec G115 // ignore Type conversion which leads to integer overflow
	for _, match := range mp.matches {
		l := match.Length()
		o := match.Offset()

		// avoid any processing if the match offset and match length exceed the size of the file
		if o+l > uint64(len(mp.fc)) {
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
