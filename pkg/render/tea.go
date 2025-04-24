package render

import (
	"context"
	"fmt"
	"io"
	"os"
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
}

type scanCompleteMsg struct{}

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("211")).
			MarginLeft(2)

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "#666666", Dark: "#999999"}).
			MarginLeft(2).
			MaxHeight(1).
			Inline(true) // Force inline rendering

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
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

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
		m.currentFile = msg.path
		return m, cmd

	case resultUpdateMsg:
		newContent := msg.content
		if len(m.content) > 0 {
			newContent = "\n" + newContent
		}

		if strings.Contains(newContent, ": permission denied") ||
			strings.Contains(newContent, "skipped") {
			m.errors = append(m.errors, strings.TrimSpace(newContent))
		} else {
			m.content = append(m.content, strings.TrimSpace(newContent))
			if msg.isResult {
				m.resultCount++
			}
		}

		// Update viewport to show both content and errors
		var displayContent []string
		displayContent = append(displayContent, m.content...)
		// if len(m.errors) > 0 {
		// 	if len(displayContent) > 0 {
		// 		displayContent = append(displayContent, "")
		// 	}
		// 	displayContent = append(displayContent, "Errors:")
		// 	displayContent = append(displayContent, m.errors...)
		// }

		m.viewport.SetContent(strings.Join(displayContent, "\n"))
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
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case scanCompleteMsg:
		m.currentFile = ""
		return m, nil
	}

	m.viewport, cmd = m.viewport.Update(msg)
	if cmd != nil {
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *mainModel) performSearch() {
	if m.searchTerm == "" {
		m.resetContent()
		return
	}

	term := strings.ToLower(m.searchTerm)
	var matchedLines []string
	var foundMatch bool

	for _, line := range m.content {
		lowerLine := strings.ToLower(line)
		if strings.Contains(lowerLine, term) {
			foundMatch = true
			lastIndex := 0
			resultLine := ""
			for {
				index := strings.Index(strings.ToLower(line[lastIndex:]), term)
				if index == -1 {
					resultLine += line[lastIndex:]
					break
				}
				resultLine += line[lastIndex : lastIndex+index]
				matchText := line[lastIndex+index : lastIndex+index+len(term)]
				resultLine += matchStyle.Render(matchText)
				lastIndex += index + len(term)
			}
			matchedLines = append(matchedLines, resultLine)
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

type Interactive struct {
	writer  io.Writer
	model   *mainModel
	program *tea.Program
	mu      sync.Mutex
	wg      sync.WaitGroup
}

func NewInteractive(w io.Writer) *Interactive {
	if w == nil {
		w = os.Stdout
	}
	model := newMainModel()
	program := tea.NewProgram(
		model,
		tea.WithAltScreen(),
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

func (r *Interactive) Start() {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		if _, err := r.program.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error running program: %v\n", err)
		}
	}()
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

	r.mu.Lock()
	defer r.mu.Unlock()

	if fr == nil {
		return nil
	}

	var content string
	switch {
	case fr.Skipped != "":
		content = fmt.Sprintf("skipped %s: %s", fr.Path, fr.Skipped)
	case len(fr.Behaviors) > 0:
		var builder strings.Builder
		renderFileSummaryTea(ctx, fr, &builder, tableConfig{
			Title: fmt.Sprintf("%s %s", fr.Path, darkBrackets(riskInColor(fr.RiskLevel))),
		})
		content = strings.TrimSpace(builder.String())
	}

	if content != "" {
		r.program.Send(resultUpdateMsg{
			content:  content,
			isResult: len(fr.Behaviors) > 0,
		})
	}

	return nil
}

func (r *Interactive) Full(ctx context.Context, _ *malcontent.Config, rep *malcontent.Report) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	defer func() {
		r.program.Send(scanCompleteMsg{})
		r.wg.Wait()
	}()

	if rep == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	processFile := func(fr *malcontent.FileReport, prefix string) {
		if fr != nil {
			var builder strings.Builder
			renderFileSummaryTea(ctx, fr, &builder, tableConfig{
				Title: fmt.Sprintf("%s: %s", prefix, fr.Path),
			})
			content := strings.TrimSpace(builder.String())
			r.program.Send(resultUpdateMsg{
				content:  content,
				isResult: true,
			})
		}
	}

	if rep.Diff != nil {
		// Process all diffs, handling any potential nil values
		for removed := rep.Diff.Removed.Oldest(); removed != nil; removed = removed.Next() {
			processFile(removed.Value, "Removed")
		}

		for added := rep.Diff.Added.Oldest(); added != nil; added = added.Next() {
			processFile(added.Value, "Added")
		}

		for modified := rep.Diff.Modified.Oldest(); modified != nil; modified = modified.Next() {
			processFile(modified.Value, "Modified")
		}
	}

	return nil
}
