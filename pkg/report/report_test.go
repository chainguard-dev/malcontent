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
	for b.Loop() {
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

func TestSkipMatch(t *testing.T) {
	tests := []struct {
		name             string
		ignoreMalcontent bool
		override         bool
		scan             bool
		risk             int
		threshold        int
		highestRisk      int
		want             bool
	}{
		{
			name:             "unmodified risk edge case",
			ignoreMalcontent: false,
			override:         false,
			scan:             false,
			risk:             -1,
			threshold:        1,
			highestRisk:      1,
			want:             true,
		},
		{
			name:             "ordinary analyze",
			ignoreMalcontent: false,
			override:         false,
			scan:             false,
			risk:             2,
			threshold:        1,
			highestRisk:      1,
			want:             false,
		},
		{
			name:             "ordinary scan with HIGH threshold",
			ignoreMalcontent: false,
			override:         false,
			scan:             true,
			risk:             2,
			threshold:        3,
			highestRisk:      3,
			want:             true,
		},
		{
			name:             "ordinary scan with HIGH risk and HIGH threshold",
			ignoreMalcontent: false,
			override:         false,
			scan:             true,
			risk:             3,
			threshold:        3,
			highestRisk:      3,
			want:             false,
		},
		{
			name:             "ordinary scan with HIGH risk and CRITICAL threshold",
			ignoreMalcontent: false,
			override:         false,
			scan:             true,
			risk:             3,
			threshold:        4,
			highestRisk:      4,
			want:             true,
		},
		{
			name:             "ordinary scan with CRITICAL risk and CRITICAL threshold",
			ignoreMalcontent: false,
			override:         false,
			scan:             true,
			risk:             4,
			threshold:        4,
			highestRisk:      4,
			want:             false,
		},
		{
			name:             "ordinary analyze with override to downgrade severity",
			ignoreMalcontent: false,
			override:         true,
			scan:             false,
			risk:             2,
			threshold:        1,
			highestRisk:      4,
			want:             false,
		},
		{
			name:             "analyze with override to upgrade severity",
			ignoreMalcontent: false,
			override:         true,
			scan:             true,
			risk:             4,
			threshold:        1,
			highestRisk:      2,
			want:             false,
		},
		{
			name:             "scan with override to upgrade severity",
			ignoreMalcontent: false,
			override:         true,
			scan:             true,
			risk:             4,
			threshold:        3,
			highestRisk:      3,
			want:             false,
		},
		{
			name:             "scan with override to downgrade severity",
			ignoreMalcontent: false,
			override:         true,
			scan:             true,
			risk:             2,
			threshold:        3,
			highestRisk:      3,
			want:             false,
		},
		{
			name:             "scan with override to upgrade severity",
			ignoreMalcontent: false,
			override:         true,
			scan:             true,
			risk:             4,
			threshold:        3,
			highestRisk:      3,
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := skipMatch(tt.ignoreMalcontent, tt.override, tt.scan, tt.risk, tt.threshold, tt.highestRisk); got != tt.want {
				t.Errorf("skipMatch(%v, %v, %v, %d, %d, %d) = %v, want %v", tt.ignoreMalcontent, tt.override, tt.scan, tt.risk, tt.threshold, tt.highestRisk, got, tt.want)
			}
		})
	}
}

func TestSkipScanFile(t *testing.T) {
	tests := []struct {
		name             string
		scan             bool
		overallRiskScore int
		want             bool
	}{
		{
			name:             "analyze with non-HIGH",
			scan:             false,
			overallRiskScore: 2,
			want:             false,
		},
		{
			name:             "analyze with HIGH",
			scan:             false,
			overallRiskScore: 3,
			want:             false,
		},
		{
			name:             "analyze with CRITICAL",
			scan:             false,
			overallRiskScore: 3,
			want:             false,
		},
		{
			name:             "scan with non-HIGH",
			scan:             true,
			overallRiskScore: 2,
			want:             true,
		},
		{
			name:             "scan with HIGH",
			scan:             true,
			overallRiskScore: 3,
			want:             false,
		},
		{
			name:             "scan with CRITICAL",
			scan:             true,
			overallRiskScore: 3,
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := skipScanFile(tt.scan, tt.overallRiskScore); got != tt.want {
				t.Errorf("skipScanFile(%v, %d) = %v, want %v", tt.scan, tt.overallRiskScore, got, tt.want)
			}
		})
	}
}

func TestApplyCriticalUpgrade(t *testing.T) {
	tests := []struct {
		name                  string
		quantityIncreasesRisk bool
		riskCounts            map[int]int
		overallRiskScore      int
		size                  int64
		want                  bool
	}{
		{
			name:                  "several highs but no increase",
			quantityIncreasesRisk: false,
			riskCounts: map[int]int{
				3: 100,
			},
			overallRiskScore: 3,
			size:             1000,
			want:             false,
		},
		{
			name:                  "several highs with increase",
			quantityIncreasesRisk: true,
			riskCounts: map[int]int{
				3: 10,
			},
			overallRiskScore: 3,
			size:             1000,
			want:             true,
		},
		{
			name:                  "no highs with increase",
			quantityIncreasesRisk: true,
			riskCounts: map[int]int{
				0: 1,
				1: 5,
				2: 100,
			},
			overallRiskScore: 2,
			size:             1000,
			want:             false,
		},
		{
			name:                  "no highs with no increase",
			quantityIncreasesRisk: false,
			riskCounts: map[int]int{
				0: 1,
				1: 1,
				2: 1,
			},
			overallRiskScore: 2,
			size:             1000,
			want:             false,
		},
		{
			name:                  "highs and criticals with no increase",
			quantityIncreasesRisk: false,
			riskCounts: map[int]int{
				3: 4,
				4: 1,
			},
			overallRiskScore: 4,
			size:             1000,
			want:             false,
		},
		{
			name:                  "highs and criticals with increase and already critical",
			quantityIncreasesRisk: true,
			riskCounts: map[int]int{
				3: 3,
				4: 1,
			},
			overallRiskScore: 4, // only 3 is a valid risk score for upgradeRisk
			size:             1.5 * 1024 * 1024,
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := applyCriticalUpgrade(context.Background(), tt.quantityIncreasesRisk, tt.riskCounts, tt.overallRiskScore, tt.size); got != tt.want {
				t.Errorf("applyCriticalUpgrade(ctx, %v, %v, %d, %d) = %v, want %v", tt.quantityIncreasesRisk, tt.riskCounts, tt.overallRiskScore, tt.size, got, tt.want)
			}
		})
	}
}

func TestIsMalcontent(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"unrelated file", "/usr/bin/foo", false},
		{"make out/mal", "out/mal", true},
		{"installed binary", "/usr/local/bin/mal", true},
		{"NAME", "malcontent", true},
		{"NAME uppercase", "MALCONTENT", true},
		{"installation to opt with NAME", "opt/malcontent", true},
		{"binary name uppercase", "out/MAL", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isMalcontent(tt.path); got != tt.want {
				t.Errorf("isMalcontent(%s) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
