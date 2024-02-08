package bincapz

type Capability struct {
	Rule        string
	RuleSource  string `json:",omitempty" yaml:",omitempty"`
	Description string `json:",omitempty" yaml:",omitempty"`
	Key         string
	Syscall     string   `json:",omitempty" yaml:",omitempty"`
	Pledge      string   `json:",omitempty" yaml:",omitempty"`
	Matched     []string `json:",omitempty" yaml:",omitempty"`
}

type FileResult struct {
	Path         string
	Capabilities []Capability
}

type Result struct {
	Files []FileResult
}
