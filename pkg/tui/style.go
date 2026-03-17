package tui

import "github.com/charmbracelet/lipgloss"

var (
	appStyle = lipgloss.NewStyle().Padding(0, 2)

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")) // Gray

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("2")). // Green
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("1")). // Red
			Bold(true)

	// 定义基础颜色
	selectedColor = lipgloss.Color("5") // Magenta (光标选中行)
)
