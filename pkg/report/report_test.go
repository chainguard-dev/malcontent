package report

import (
	"context"
	"reflect"
	"testing"
)

func TestLongestUnique(t *testing.T) {
	tests := []struct {
		name string
		raw  []string
		want []string
	}{
		{
			name: "Test 1",
			raw:  []string{"apple", "banana", "cherry", "applecherry", "bananaapple", "cherrybanana"},
			want: []string{"cherrybanana", "applecherry", "bananaapple"},
		},
		{
			name: "Test 2",
			raw:  []string{"test", "testing", "tester", "testest"},
			want: []string{"testing", "testest", "tester"},
		},
		{
			name: "Test 3",
			raw:  []string{"", "a", "aa", "aaa"},
			want: []string{"aaa"},
		},
		{
			name: "Test 4",
			raw:  []string{"abc", "def", "ghi"},
			want: []string{"abc", "def", "ghi"},
		},
		{
			name: "Test 5",
			raw:  []string{"abc", "abcabc", "abcabcabc"},
			want: []string{"abcabcabc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := longestUnique(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("longestUnique() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkLongestUnique(b *testing.B) {
	raw := []string{
		"_proc_download_content",
		"apple",
		"applecherry",
		"banana",
		"bananaapple",
		"cherry",
		"cherrybanana",
		"upload_content",
	}
	for i := 0; i < b.N; i++ {
		longestUnique(raw)
	}
}

func TestUpgradeRisk(t *testing.T) {
	tests := []struct {
		name         string
		currentScore int
		riskCounts   map[int]int
		size         int64
		want         bool
	}{
		{"no risk", 0, map[int]int{}, 1024, false},
		{"tiny-risky", 3, map[int]int{3: 2}, 310, true},
		{"small-not", 3, map[int]int{3: 2}, 8192, false},
		{"small-risky", 3, map[int]int{3: 3}, 8192, true},
		{"large-not", 3, map[int]int{3: 3}, 1024 * 1024 * 1024, false},
		{"large-yes", 3, map[int]int{3: 10}, 1024 * 1024 * 1024, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := upgradeRisk(context.Background(), tt.currentScore, tt.riskCounts, tt.size); got != tt.want {
				t.Errorf("upgradeRisk(%d, %v, %v) = %v, want %v", tt.currentScore, tt.riskCounts, tt.size, got, tt.want)
			}
		})
	}
}
