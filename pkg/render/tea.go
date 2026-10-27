// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type scanUpdateMsg struct {
	path string
}

type resultUpdateMsg struct {
	content  string
	isResult bool
	// isError marks content that reports a file the scan skipped, which the
	// viewer keeps apart from the results.
	isError bool
}

type scanCompleteMsg struct{}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("211")).
			MarginLeft(2)

	// Inline rendering keeps the footer on one line and applies no margins.
	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#666666", Dark: "#999999"}).
			Inline(true)

	viewportStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("62")).
			Padding(1, 2)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))

	searchPromptStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("62")).
				Foreground(lipgloss.Color("230")).
				Padding(0, 1)

	matchStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("62")).
			Foreground(lipgloss.Color("230"))

	progressStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("205"))
)

type mainModel struct {
	content     []string
	currentFile string
	errors      []string
	height      int
	quitting    bool
	ready       bool
	resultCount int
	searchMode  bool
	searchTerm  string
	spinner     spinner.Model
	viewport    viewport.Model
	width       int
}

func newMainModel() mainModel {
	s := spinner.New()
	style := spinner.Spinner{
		Frames: []string{"🔍", "🔎"},
		FPS:    time.Second / 4,
	}
	s.Spinner = style
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return mainModel{
		content:    make([]string, 0),
		quitting:   false,
		ready:      false,
		searchMode: false,
		spinner:    s,
	}
}

func (m mainModel) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		m.spinner.Tick,
	)
}

func (m mainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		headerHeight := 3
		footerHeight := 2
		verticalMarginHeight := headerHeight + footerHeight

		if !m.ready {
			m.viewport = viewport.New(msg.Width-4, msg.Height-verticalMarginHeight)
			m.viewport.Style = viewportStyle
			m.viewport.SetContent(strings.Join(m.content, "\n"))
			m.ready = true
		} else {
			m.viewport.Width = msg.Width - 4
			m.viewport.Height = msg.Height - verticalMarginHeight
		}
		m.width = msg.Width
		m.height = msg.Height

	case scanUpdateMsg:
		m.currentFile = sanitizeTerminal(msg.path)
		return m, cmd

	case resultUpdateMsg:
		content := strings.TrimSpace(msg.content)
		if msg.isError {
			m.errors = append(m.errors, content)
		} else {
			m.content = append(m.content, content)
			if msg.isResult {
				m.resultCount++
			}
		}

		m.viewport.SetContent(strings.Join(m.content, "\n"))
		m.viewport.GotoBottom()
		return m, cmd

	case tea.KeyMsg:
		if m.searchMode {
			switch msg.String() {
			case "esc":
				m.searchMode = false
				m.searchTerm = ""
				m.resetContent()
			case "enter":
				m.searchMode = false
				m.performSearch()
			case "backspace":
				if len(m.searchTerm) > 0 {
					m.searchTerm = m.searchTerm[:len(m.searchTerm)-1]
					m.performSearch()
				}
			default:
				if len(msg.String()) == 1 {
					m.searchTerm += msg.String()
					m.performSearch()
				}
			}
			return m, nil
		}

		// Keys handled here are not forwarded to the viewport: it binds several
		// of the same keys and would scroll a second time.
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			m.viewport.ScrollUp(1)
		case "down", "j":
			m.viewport.ScrollDown(1)
		case "pgup":
			m.viewport.HalfPageUp()
		case "pgdown":
			m.viewport.HalfPageDown()
		case "home":
			m.viewport.GotoTop()
		case "end":
			m.viewport.GotoBottom()
		case "/":
			m.searchMode = true
			m.searchTerm = ""
		default:
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case scanCompleteMsg:
		m.currentFile = ""
		return m, nil
	}

	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m *mainModel) performSearch() {
	if m.searchTerm == "" {
		m.resetContent()
		return
	}

	re := regexp.MustCompile("(?i)" + regexp.QuoteMeta(m.searchTerm))
	var matchedLines []string
	var foundMatch bool

	for _, line := range m.content {
		if highlighted, ok := highlightMatches(line, re); ok {
			foundMatch = true
			matchedLines = append(matchedLines, highlighted)
		} else if foundMatch {
			matchedLines = append(matchedLines, line)
			foundMatch = false
		}
	}

	if len(matchedLines) > 0 {
		m.viewport.SetContent(strings.Join(matchedLines, "\n"))
	} else {
		m.viewport.SetContent("No matches found for: " + m.searchTerm)
	}
}

// ansiEscapeRe matches the CSI escape sequences that styled lines carry, such
// as SGR color sequences.
var ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

// highlightMatches returns line with each match of re in its visible text
// highlighted, and whether there was one. It matches on the line itself, so
// case folding cannot shift a match off the bytes it covers, and it skips the
// escape sequences in the line, so a term cannot match or split one.
func highlightMatches(line string, re *regexp.Regexp) (string, bool) {
	var b strings.Builder
	found := false
	last := 0
	// The final pair stands for an empty sequence at the end of the line.
	escapes := append(ansiEscapeRe.FindAllStringIndex(line, -1), []int{len(line), len(line)})
	for _, esc := range escapes {
		text := line[last:esc[0]]
		at := 0
		for _, match := range re.FindAllStringIndex(text, -1) {
			found = true
			b.WriteString(text[at:match[0]])
			b.WriteString(matchStyle.Render(text[match[0]:match[1]]))
			at = match[1]
		}
		b.WriteString(text[at:])
		b.WriteString(line[esc[0]:esc[1]])
		last = esc[1]
	}
	return b.String(), found
}

func (m *mainModel) resetContent() {
	m.viewport.SetContent(strings.Join(m.content, "\n"))
}

func (m mainModel) View() string {
	var b strings.Builder

	// Render header with controls
	header := titleStyle.Render("malcontent scan results")
	controls := helpStyle.Render("↑/↓: scroll • /: search • q: quit")
	gap := strings.Repeat(" ", max(0, m.width-lipgloss.Width(header)-lipgloss.Width(controls)))
	headerLine := lipgloss.JoinHorizontal(lipgloss.Center, header, gap, controls)
	b.WriteString(headerLine)
	b.WriteString("\n")

	// Render scan status if active
	if m.currentFile != "" {
		scanLine := progressStyle.Render(fmt.Sprintf("%s Scanning: %s", m.spinner.View(), m.currentFile))
		b.WriteString(scanLine)
		b.WriteString("\n")
	}

	// Render search bar if in search mode
	if m.searchMode {
		prompt := searchPromptStyle.Render("Search:")
		cursor := m.searchTerm + "█"
		searchLine := lipgloss.JoinHorizontal(lipgloss.Left, prompt, " ", cursor)
		b.WriteString(searchLine)
		b.WriteString("\n")
	}

	// Viewport content
	b.WriteString(m.viewport.View())

	// Single line footer
	footerContent := fmt.Sprintf("Found %d results", m.resultCount)
	if m.searchMode && m.searchTerm != "" {
		footerContent += fmt.Sprintf(" (searching for: %q)", m.searchTerm)
	}
	footer := statusStyle.Width(m.width).Render(footerContent)

	// Ensure footer is rendered below viewport with proper spacing
	return fmt.Sprintf("%s\n%s", strings.TrimRight(b.String(), "\n"), footer)
}

// Interactive shows the reports in a full-screen viewer, which runs from
// Start until the user quits it or Stop ends it.
type Interactive struct {
	writer  io.Writer
	model   *mainModel
	program *tea.Program
	mu      sync.Mutex
	wg      sync.WaitGroup
	// runErr is the error the viewer ended with. It is set before wg is
	// done, so it may be read once wg.Wait returns.
	runErr error
}

// NewInteractive returns a viewer that draws to w, or to os.Stdout when w is nil.
func NewInteractive(w io.Writer) *Interactive {
	if w == nil {
		w = os.Stdout
	}
	model := newMainModel()
	program := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithOutput(w),
	)

	return &Interactive{
		writer:  w,
		model:   &model,
		program: program,
	}
}

func (r *Interactive) Name() string {
	return "Interactive"
}

// Start runs the viewer in the background. Full returns the error it ends
// with, such as one for a panic it recovered from.
func (r *Interactive) Start() {
	r.wg.Go(func() {
		_, r.runErr = r.program.Run()
	})
}

// Stop ends the viewer started by Start without waiting for the user and
// returns once it has restored the terminal. It does nothing more when the
// viewer has already ended.
func (r *Interactive) Stop() {
	r.program.Quit()
	r.wg.Wait()
}

func (r *Interactive) Scanning(ctx context.Context, path string) {
	if ctx.Err() != nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.program.Send(scanUpdateMsg{path: path})
}

func (r *Interactive) File(ctx context.Context, fr *malcontent.FileReport) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if fr == nil {
		return nil
	}

	// Render before taking the lock, so concurrent File calls render in
	// parallel and only their messages are sent one at a time.
	var msg resultUpdateMsg
	if fr.Skipped != "" {
		msg = resultUpdateMsg{content: "skipped " + sanitizeTerminal(fr.Path) + ": " + sanitizeTerminal(fr.Skipped), isError: true}
	} else if len(fr.Behaviors) > 0 {
		var builder strings.Builder
		renderFileSummaryTea(ctx, fr, teaScanHeader(fr), &builder)
		msg = resultUpdateMsg{content: strings.TrimSpace(builder.String()), isResult: true}
	}

	if msg.content == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.program.Send(msg)
	return nil
}

// Full sends the files of a diff whose behaviors changed, titled as the
// terminal renderer titles them, then waits for the viewer to end and
// returns the error it ended with.
func (r *Interactive) Full(ctx context.Context, _ *malcontent.Config, rep *malcontent.Report) (err error) {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	defer func() {
		r.program.Send(scanCompleteMsg{})
		r.wg.Wait()
		err = errors.Join(err, r.runErr)
	}()

	if rep == nil || rep.Diff == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	send := func(fr *malcontent.FileReport, header string) {
		var builder strings.Builder
		renderFileSummaryTea(ctx, fr, header, &builder)
		if content := strings.TrimSpace(builder.String()); content != "" {
			r.program.Send(resultUpdateMsg{content: content, isResult: true})
		}
	}

	for _, section := range []struct {
		files *malcontent.OrderedFileReports
		label string
	}{{rep.Diff.Removed, "Deleted: "}, {rep.Diff.Added, "Added: "}} {
		for p := section.files.Oldest(); p != nil; p = p.Next() {
			if len(p.Value.Behaviors) == 0 {
				continue
			}
			send(p.Value, teaHeader(section.label+sanitizeTerminal(p.Key), p.Value.RiskLevel))
		}
	}

	// Like the other renderers, only report modified files whose behaviors changed.
	for p := rep.Diff.Modified.Oldest(); p != nil; p = p.Next() {
		added, removed := diffCounts(p.Value.Behaviors)
		if added == 0 && removed == 0 {
			continue
		}
		send(p.Value, teaDiffHeader(p.Value, added, removed))
	}

	return nil
}
