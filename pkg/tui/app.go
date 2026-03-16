package tui

import (
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/wentf9/xops-cli/pkg/config"
)

type viewState int

const (
	viewList viewState = iota
	viewForm
)

type Model struct {
	provider    config.ConfigProvider
	configStore config.Store
	list        list.Model
	form        *huh.Form
	formState   *nodeFormState
	state       viewState
}

// NewModel initializes the TUI model.
func NewModel(provider config.ConfigProvider, configStore config.Store) Model {
	m := Model{
		provider:    provider,
		configStore: configStore,
		state:       viewList,
	}
	m.list = newListModel(provider)
	return m
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	switch m.state {
	case viewList:
		m, cmd = m.updateList(msg)
	case viewForm:
		m, cmd = m.updateForm(msg)
	}
	return m, cmd
}

func (m Model) View() string {
	switch m.state {
	case viewList:
		return appStyle.Render(m.list.View())
	case viewForm:
		if m.form != nil {
			return appStyle.Render(m.form.View())
		}
		return "Form View (WIP)"
	default:
		return ""
	}
}
