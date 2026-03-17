package tui

import (
	"time"

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
	provider      config.ConfigProvider
	configStore   config.Store
	list          list.Model
	form          *huh.Form
	formState     *nodeFormState
	state         viewState
	status        string
	lastSize      tea.WindowSizeMsg
	deletePending bool
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

type tickMsg time.Time

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.lastSize = msg
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case tickMsg:
		// 只有在非删除确认状态下，才自动清除状态
		if !m.deletePending {
			m.status = ""
			if m.state == viewList {
				*m, _ = m.updateList(m.lastSize)
			}
		}
		return m, nil
	}

	var cmd tea.Cmd
	oldState := m.state
	switch m.state {
	case viewList:
		*m, cmd = m.updateList(msg)
	case viewForm:
		*m, cmd = m.updateForm(msg)
	}

	// If we just switched from form to list, force a resize
	if oldState == viewForm && m.state == viewList {
		*m, _ = m.updateList(m.lastSize)
	}

	// If status was just set, start a timer to clear it
	// 但如果是删除确认状态，我们不希望它自动消失
	if m.status != "" && !m.deletePending {
		return m, tea.Batch(cmd, tea.Tick(time.Second*3, func(t time.Time) tea.Msg {
			return tickMsg(t)
		}))
	}

	return m, cmd
}

func (m Model) View() string {
	var s string
	switch m.state {
	case viewList:
		s = m.list.View()
	case viewForm:
		if m.form != nil {
			s = m.form.View()
		} else {
			s = "Form View (WIP)"
		}
	}

	if m.status != "" {
		s += "\n\n" + statusStyle.Render(m.status)
	}

	return appStyle.Render(s)
}
