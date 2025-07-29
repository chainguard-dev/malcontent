package report

import (
	"slices"
	"sync"

	yarax "github.com/VirusTotal/yara-x/go"
)

// StringPool holds data to handle string interning.
type StringPool struct {
	sync.RWMutex
	strings map[string]string
}

// clear removes all strings from the pool to free memory.
func (sp *StringPool) clear() {
	sp.Lock()
	defer sp.Unlock()
	clear(sp.strings)
}

// NewStringPool creates a new string pool.
func NewStringPool(length int) *StringPool {
	return &StringPool{
		strings: make(map[string]string, length),
	}
}

// Intern returns an interned version of the input string.
func (sp *StringPool) Intern(s string) string {
	sp.RLock()
	defer sp.RUnlock()
	if interned, ok := sp.strings[s]; ok {
		return interned
	}

	sp.strings[s] = s
	return s
}

type matchProcessor struct {
	fc       []byte
	pool     *StringPool
	matches  []yarax.Match
	patterns []yarax.Pattern
	mu       sync.Mutex
}

func newMatchProcessor(fc []byte, matches []yarax.Match, mp []yarax.Pattern) *matchProcessor {
	return &matchProcessor{
		fc:       fc,
		pool:     NewStringPool(len(matches)),
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

	mp.mu.Lock()
	defer mp.mu.Unlock()

	var result *[]string
	var ok bool
	if result, ok = matchResultPool.Get().(*[]string); !ok {
		s := make([]string, 0, len(mp.matches))
		result = &s
	}

	// Return early if neither the pool nor the make result in a usable slice
	if result == nil {
		return nil
	}

	ret := (*result)[:0]
	defer matchResultPool.Put(&ret)

	// #nosec G115 // ignore Type conversion which leads to integer overflow
	for _, match := range mp.matches {
		l := match.Length()
		o := match.Offset()

		// avoid any processing if the match offset and match length exceed the size of the file
		if o+l > uint64(len(mp.fc)) {
			continue
		}

		matchBytes := (mp.fc)[o : o+l]

		switch !containsUnprintable(matchBytes) {
		case true:
			var matchStr string
			if l <= uint64(cap(matchBytes)) {
				matchStr = string(append([]byte(nil), matchBytes[:l]...))
			} else {
				matchStr = string(matchBytes)
			}
			*result = append(*result, mp.pool.Intern(matchStr))
		default:
			patterns := make([]string, 0, len(mp.patterns))
			for _, p := range mp.patterns {
				patterns = append(patterns, mp.pool.Intern(p.Identifier()))
			}
			*result = append(*result, slices.Compact(patterns)...)
		}
	}

	return append([]string{}, *result...)
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
