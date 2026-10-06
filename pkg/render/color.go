// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"os"
	"strings"

	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/fatih/color"
)

// sgr holds the escape sequences fatih/color writes around text for one set
// of attributes. They are captured from the library once, so rendering writes
// the same bytes the library would without rebuilding them on every call.
type sgr struct {
	// on starts the attributes.
	on string
	// off ends them the way Sprint, Fprintln, and the *String helpers do.
	off string
	// printOff ends them the way Fprint does.
	printOff string
}

// newSGR captures the sequences c writes when color is on.
func newSGR(c *color.Color) sgr {
	c.EnableColor()
	on, off, _ := strings.Cut(c.Sprint("\x00"), "\x00")
	var b strings.Builder
	_, _ = c.Fprint(&b, "\x00")
	_, printOff, _ := strings.Cut(b.String(), "\x00")
	return sgr{on: on, off: off, printOff: printOff}
}

// wrap writes text to b between s.on and s.off.
func (s sgr) wrap(b *bytes.Buffer, text string) {
	b.WriteString(s.on)
	b.WriteString(text)
	b.WriteString(s.off)
}

// sprint returns text between s.on and s.off. With both empty, the
// concatenation returns text itself without allocating.
func (s sgr) sprint(text string) string {
	return s.on + text + s.off
}

// palette holds the attribute sets the text renderers draw with.
type palette struct {
	plain     sgr // color.New() without attributes
	hiBlack   sgr
	hiRed     sgr
	hiGreen   sgr
	hiYellow  sgr
	hiMagenta sgr
	hiCyan    sgr
	hiWhite   sgr
	white     sgr
	evidence  sgr // color.RGB(255, 255, 255)
}

var (
	colorPalette = palette{
		plain:     newSGR(color.New()),
		hiBlack:   newSGR(color.New(color.FgHiBlack)),
		hiRed:     newSGR(color.New(color.FgHiRed)),
		hiGreen:   newSGR(color.New(color.FgHiGreen)),
		hiYellow:  newSGR(color.New(color.FgHiYellow)),
		hiMagenta: newSGR(color.New(color.FgHiMagenta)),
		hiCyan:    newSGR(color.New(color.FgHiCyan)),
		hiWhite:   newSGR(color.New(color.FgHiWhite)),
		white:     newSGR(color.New(color.FgWhite)),
		evidence:  newSGR(color.RGB(255, 255, 255)),
	}

	// plainPalette writes no escape sequences, as fatih/color does when color is off.
	plainPalette palette
)

// currentPalette returns the palette that matches fatih/color's setting at
// the time of the call: plain when color.NoColor is set or NO_COLOR is not
// empty.
func currentPalette() *palette {
	if color.NoColor || os.Getenv("NO_COLOR") != "" {
		return &plainPalette
	}
	return &colorPalette
}

// risk returns the attribute set that marks a risk level in terminal output.
func (p *palette) risk(level string) sgr {
	switch level {
	case report.LevelLOW:
		return p.hiCyan
	case report.LevelMEDIUM, "MED":
		return p.hiYellow
	case report.LevelHIGH:
		return p.hiRed
	case report.LevelCRITICAL, levelCRIT:
		return p.hiMagenta
	default:
		return p.white
	}
}

// briefRisk returns the attribute set and the abbreviated label for a risk
// level in string match output.
func (p *palette) briefRisk(level string) (sgr, string) {
	switch level {
	case report.LevelLOW:
		return p.hiGreen, report.LevelLOW
	case report.LevelMEDIUM, "MED":
		return p.hiYellow, "MED"
	case report.LevelHIGH:
		return p.hiRed, report.LevelHIGH
	case report.LevelCRITICAL, levelCRIT:
		return p.hiMagenta, levelCRIT
	default:
		return p.white, level
	}
}
