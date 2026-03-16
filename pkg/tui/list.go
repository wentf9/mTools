package tui

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wentf9/xops-cli/pkg/config"
)

type nodeItem struct {
	id       string
	name     string
	address  string
	user     string
	tags     string
	selected bool
}

func (i nodeItem) Title() string {
	prefix := "[ ] "
	if i.selected {
		prefix = "[x] "
	}
	return prefix + i.name
}
func (i nodeItem) Description() string { return fmt.Sprintf("%s@%s - [%s]", i.user, i.address, i.tags) }
func (i nodeItem) FilterValue() string {
	return i.id + " " + i.name + " " + i.address + " " + i.user + " " + i.tags
}

func newListModel(provider config.ConfigProvider) list.Model {
	nodes := provider.ListNodes()
	var items []list.Item

	for id, node := range nodes {
		identity, _ := provider.GetIdentity(id)
		host, _ := provider.GetHost(id)

		name := id
		if len(node.Alias) > 0 {
			name = node.Alias[0]
		}

		items = append(items, nodeItem{
			id:      id,
			name:    name,
			address: host.Address,
			user:    identity.User,
			tags:    strings.Join(node.Tags, ","),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].(nodeItem).name < items[j].(nodeItem).name
	})

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Host Management"
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)

	// Add custom help keys
	l.AdditionalShortHelpKeys = func() []key.Binding {
		return []key.Binding{
			key.NewBinding(key.WithKeys("space"), key.WithHelp("space", "select")),
			key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "all")),
			key.NewBinding(key.WithKeys("v"), key.WithHelp("v", "invert")),
			key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "delete")),
			key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "edit")),
			key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "new")),
		}
	}

	return l
}

func (m Model) updateList(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h, v := appStyle.GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v)
		return m, nil

	case tea.KeyMsg:
		if m.list.SettingFilter() {
			break
		}
		switch msg.String() {
		case "enter":
			return m.handleEnter()
		case " ":
			return m.handleSpace()
		case "a":
			return m.handleSelectAll()
		case "v":
			return m.handleInvertSelection()
		case "d":
			return m.handleDelete()
		case "n":
			return m.handleNew()
		case "e":
			return m.handleEdit()
		case "esc", "q", "ctrl+c":
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m Model) handleEnter() (Model, tea.Cmd) {
	selected := m.list.SelectedItem()
	if selected != nil {
		nodeID := selected.(nodeItem).id
		return m, runSSH(nodeID)
	}
	return m, nil
}

func (m Model) handleSpace() (Model, tea.Cmd) {
	idx := m.list.Index()
	selectedItem, ok := m.list.SelectedItem().(nodeItem)
	if ok {
		selectedItem.selected = !selectedItem.selected
		cmd := m.list.SetItem(idx, selectedItem)
		return m, cmd
	}
	return m, nil
}

func (m Model) handleSelectAll() (Model, tea.Cmd) {
	var newItems []list.Item
	for _, i := range m.list.Items() {
		ni := i.(nodeItem)
		ni.selected = true
		newItems = append(newItems, ni)
	}
	cmd := m.list.SetItems(newItems)
	return m, cmd
}

func (m Model) handleInvertSelection() (Model, tea.Cmd) {
	var newItems []list.Item
	for _, i := range m.list.Items() {
		ni := i.(nodeItem)
		ni.selected = !ni.selected
		newItems = append(newItems, ni)
	}
	cmd := m.list.SetItems(newItems)
	return m, cmd
}

func (m Model) handleDelete() (Model, tea.Cmd) {
	var toDelete []string
	for _, i := range m.list.Items() {
		if ni, ok := i.(nodeItem); ok && ni.selected {
			toDelete = append(toDelete, ni.id)
		}
	}
	// 如果没有选中的，则删除当前悬停的
	if len(toDelete) == 0 {
		if sel, ok := m.list.SelectedItem().(nodeItem); ok {
			toDelete = append(toDelete, sel.id)
		}
	}
	if len(toDelete) > 0 {
		for _, id := range toDelete {
			m.provider.DeleteNode(id)
		}
		_ = m.configStore.Save(m.provider.GetConfig())
		// 刷新列表
		m.list = newListModel(m.provider)
	}
	return m, nil
}

func (m Model) handleNew() (Model, tea.Cmd) {
	m = m.initForm("")
	m.state = viewForm
	return m, nil
}

func (m Model) handleEdit() (Model, tea.Cmd) {
	selected := m.list.SelectedItem()
	if selected != nil {
		nodeID := selected.(nodeItem).id
		m = m.initForm(nodeID)
		m.state = viewForm
		return m, nil
	}
	return m, nil
}

type sshFinishedMsg struct{ err error }

func runSSH(nodeID string) tea.Cmd {
	c := os.Args[0]
	cmd := exec.Command(c, "ssh", nodeID)
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return sshFinishedMsg{err}
	})
}
