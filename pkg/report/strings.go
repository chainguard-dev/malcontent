package report

import (
	"slices"
	"sync"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/chainguard-dev/malcontent/pkg/pool"
)

var (
	initializeOnce sync.Once
	matchPool      *pool.BufferPool
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
	if len(mp.matches) == 0 {
		return nil
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()

	var result *[]string
	var ok bool
	if result, ok = matchResultPool.Get().(*[]string); ok {
		*result = (*result)[:0]
	} else {
		slice := make([]string, 0, 32)
		result = &slice
	}
	defer matchResultPool.Put(result)

	initializeOnce.Do(func() {
		matchPool = pool.NewBufferPool(len(mp.matches))
	})

	buffer := matchPool.Get(8) //nolint:nilaway // the buffer pool is created above
	defer matchPool.Put(buffer)

	patternsCap := len(mp.patterns)
	var patterns []string

	// #nosec G115 // ignore Type conversion which leads to integer overflow
	for _, match := range mp.matches {
		l := int(match.Length())
		o := int(match.Offset())

		// if the match processor's file content is nil,
		// or the offset is less than zero,
		// or the match length + offset exceeds the size of the file,
		// avoid any processing and continue
		if len(mp.fc) == 0 || o < 0 || o+l > len(mp.fc) {
			continue
		}

		matchBytes := (mp.fc)[o : o+l]

		if !containsUnprintable(matchBytes) {
			if l <= cap(buffer) {
				buffer = buffer[:l]
				copy(buffer, matchBytes)
				matchStr := string(buffer)
				*result = append(*result, mp.pool.Intern(string([]byte(matchStr))))
			} else {
				matchStr := string(matchBytes)
				*result = append(*result, mp.pool.Intern(string([]byte(matchStr))))
			}
		} else {
			if patterns == nil || cap(patterns) < patternsCap {
				patterns = make([]string, 0, patternsCap)
			} else {
				clear(patterns)
				patterns = patterns[:0]
			}
			for _, p := range mp.patterns {
				patterns = append(patterns, p.Identifier())
			}
			compacted := slices.Compact(patterns)
			*result = append(*result, compacted...)
		}
	}

	finalResult := make([]string, len(*result))
	copy(finalResult, *result)

	return finalResult
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
