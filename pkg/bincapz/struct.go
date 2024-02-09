package bincapz

type Behavior struct {
	Description string `json:",omitempty" yaml:",omitempty"`
	Risk        int
}

type FileReport struct {
	// compiler -> x
	Meta              map[string]string `json:",omitempty" yaml:",omitempty"`
	Syscalls          []string          `json:",omitempty" yaml:",omitempty"`
	Pledge            []string          `json:",omitempty" yaml:",omitempty"`
	Capabililies      []string          `json:",omitempty" yaml:",omitempty"`
	Behaviors         map[string]Behavior
	FilteredBehaviors int `json:",omitempty" yaml:",omitempty"`
}

type Report struct {
	Files  map[string]FileReport
	Filter string
}
