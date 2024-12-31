package report

import (
	"slices"
	"sync"

	yarax "github.com/VirusTotal/yara-x/go"
)

// Number of strings to process at any given time.
const batchSize = 4096

// StringPool holds data to handle string interning.
type StringPool struct {
	sync.RWMutex
	strings map[string]string
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
	if interned, ok := sp.strings[s]; ok {
		sp.RUnlock()
		return interned
	}
	sp.RUnlock()

	sp.Lock()
	defer sp.Unlock()

	if interned, ok := sp.strings[s]; ok {
		return interned
	}

	sp.strings[s] = s
	return s
}

var BufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0, 1024)
	},
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
		pool:     NewStringPool(len(matches)),
		matches:  matches,
		patterns: mp,
	}
}

var matchResultPool = sync.Pool{
	New: func() interface{} {
		s := make([]string, 0, 32)
		return &s
	},
}

// process performantly handles the conversion of matched data to strings.
// yara-x does not expose the rendered string via the API due to performance overhead.
func (mp *matchProcessor) process() []string {
	if len(mp.matches) == 0 {
		return nil
	}

	var result *[]string
	var ok bool
	if result, ok = matchResultPool.Get().(*[]string); ok {
		*result = (*result)[:0]
	} else {
		slice := make([]string, 0, 32)
		result = &slice
	}
	defer matchResultPool.Put(result)

	var buffer *[]byte
	if tmp := BufferPool.Get(); tmp != nil {
		if b, ok := tmp.(*[]byte); ok {
			buffer = b
		} else {
			slice := make([]byte, 0, 32)
			buffer = &slice
		}
	}
	defer BufferPool.Put(buffer)

	for i := 0; i < len(mp.matches); i += batchSize {
		end := i + batchSize
		if end > len(mp.matches) {
			end = len(mp.matches)
		}

		// #nosec G115 // ignore converting uint64 values to int
		for _, match := range mp.matches[i:end] {
			l := int(match.Length())
			o := int(match.Offset())

			if o < 0 || o+l > len(mp.fc) {
				continue
			}

			matchBytes := mp.fc[o : o+l]

			var str string
			if !containsUnprintable(matchBytes) {
				str = mp.pool.Intern(string(matchBytes))
				*result = append(*result, str)
			} else {
				patterns := make([]string, 0, len(mp.patterns))
				for _, p := range mp.patterns {
					patterns = append(patterns, p.Identifier())
				}
				*result = append(*result, slices.Compact(patterns)...)
			}
		}
	}

	return *result
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
