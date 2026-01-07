package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Finding represents a security finding for display.
type Finding struct {
	Name     string
	Severity string
	URL      string
}

// Model is the Bubbletea model for the TUI.
type Model struct {
	Target   string
	Findings []Finding
	Progress float64
	Spinner  spinner.Model
	ProgBar  progress.Model
	Done     bool
	Err      error
	Width    int
	Height   int
}

// Messages
type TickMsg struct{}
type ProgressMsg float64
type FindingMsg Finding
type DoneMsg struct{}
type ErrMsg struct{ Err error }

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("86")).
			MarginBottom(1)

	findingStyle = lipgloss.NewStyle().
			PaddingLeft(2)

	criticalStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true) // Red
	highStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))            // Orange
	mediumStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))            // Yellow
	lowStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("40"))             // Green
	infoStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))             // Blue

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			MarginTop(1)
)

// NewModel creates a new TUI model.
func NewModel(target string) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("86"))

	p := progress.New(progress.WithDefaultGradient())

	return Model{
		Target:   target,
		Findings: []Finding{},
		Progress: 0,
		Spinner:  s,
		ProgBar:  p,
		Done:     false,
	}
}

// Init initializes the model.
func (m Model) Init() tea.Cmd {
	return m.Spinner.Tick
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.ProgBar.Width = msg.Width - 4

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.Spinner, cmd = m.Spinner.Update(msg)
		return m, cmd

	case ProgressMsg:
		m.Progress = float64(msg)
		cmd := m.ProgBar.SetPercent(m.Progress)
		return m, cmd

	case FindingMsg:
		m.Findings = append(m.Findings, Finding(msg))
		return m, nil

	case DoneMsg:
		m.Done = true
		return m, nil

	case ErrMsg:
		m.Err = msg.Err
		return m, tea.Quit

	case progress.FrameMsg:
		progressModel, cmd := m.ProgBar.Update(msg)
		m.ProgBar = progressModel.(progress.Model)
		return m, cmd
	}

	return m, nil
}

// View renders the TUI.
func (m Model) View() string {
	var b strings.Builder

	// Title
	title := titleStyle.Render("🛡️  ScoutSec - Security Scanner")
	b.WriteString(title + "\n\n")

	// Target
	b.WriteString(fmt.Sprintf("Target: %s\n\n", m.Target))

	// Progress
	if !m.Done {
		b.WriteString(m.Spinner.View() + " Scanning...\n")
	} else {
		b.WriteString("✓ Scan Complete\n")
	}
	b.WriteString(m.ProgBar.View() + "\n\n")

	// Findings
	b.WriteString(fmt.Sprintf("Findings (%d):\n", len(m.Findings)))
	maxFindings := 10
	start := 0
	if len(m.Findings) > maxFindings {
		start = len(m.Findings) - maxFindings
	}
	for _, f := range m.Findings[start:] {
		sevStyle := getSeverityStyle(f.Severity)
		line := fmt.Sprintf("  [%s] %s - %s",
			sevStyle.Render(f.Severity),
			f.Name,
			f.URL,
		)
		b.WriteString(findingStyle.Render(line) + "\n")
	}

	// Help
	b.WriteString(helpStyle.Render("\nPress 'q' to quit"))

	return b.String()
}

func getSeverityStyle(severity string) lipgloss.Style {
	switch strings.ToLower(severity) {
	case "critical":
		return criticalStyle
	case "high":
		return highStyle
	case "medium":
		return mediumStyle
	case "low":
		return lowStyle
	default:
		return infoStyle
	}
}

// Run starts the TUI program.
func Run(target string) error {
	p := tea.NewProgram(NewModel(target), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
