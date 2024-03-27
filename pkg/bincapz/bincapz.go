package bincapz

type Behavior struct {
	Description string `json:",omitempty" yaml:",omitempty"`
	// Values are critical values to be surfaced in the UI
	Values []string `json:",omitempty" yaml:",omitempty"`
	// MatchStrings are all strings found relating to this behavior
	MatchStrings []string `json:",omitempty" yaml:",omitempty"`
	RiskScore    int
	RiskLevel    string `json:",omitempty" yaml:",omitempty"`
	RuleAuthor   string `json:",omitempty" yaml:",omitempty"`
	RuleLicense  string `json:",omitempty" yaml:",omitempty"`

	DiffAdded   bool `json:",omitempty" yaml:",omitempty"`
	DiffRemoved bool `json:",omitempty" yaml:",omitempty"`
}

type FileReport struct {
	Path   string
	SHA256 string
	// compiler -> x
	Error             string              `json:",omitempty" yaml:",omitempty"`
	Skipped           string              `json:",omitempty" yaml:",omitempty"`
	Meta              map[string]string   `json:",omitempty" yaml:",omitempty"`
	Syscalls          []string            `json:",omitempty" yaml:",omitempty"`
	Pledge            []string            `json:",omitempty" yaml:",omitempty"`
	Capabilities      []string            `json:",omitempty" yaml:",omitempty"`
	Behaviors         map[string]Behavior `json:",omitempty" yaml:",omitempty"`
	FilteredBehaviors int                 `json:",omitempty" yaml:",omitempty"`

	PreviousRiskScore int    `json:",omitempty" yaml:",omitempty"`
	PreviousRiskLevel string `json:",omitempty" yaml:",omitempty"`

	RiskScore int
	RiskLevel string `json:",omitempty" yaml:",omitempty"`
}

type DiffReport struct {
	Added    map[string]FileReport `json:",omitempty" yaml:",omitempty"`
	Removed  map[string]FileReport `json:",omitempty" yaml:",omitempty"`
	Modified map[string]FileReport `json:",omitempty" yaml:",omitempty"`
}

type Report struct {
	Files  map[string]FileReport `json:",omitempty" yaml:",omitempty"`
	Diff   DiffReport            `json:",omitempty" yaml:",omitempty"`
	Filter string                `json:",omitempty" yaml:",omitempty"`
}
