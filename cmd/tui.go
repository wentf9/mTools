package cmd

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/tui"
)

func NewCmdTui() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: i18n.T("tui_short"),
		Long:  i18n.T("tui_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			configStore := config.NewDefaultStore(utils.GetConfigFilePath())
			cfg, err := configStore.Load()
			if err != nil {
				return fmt.Errorf("%s: %w", i18n.T("config_load_error"), err)
			}
			provider := config.NewProvider(cfg)

			model := tui.NewModel(provider, configStore)
			p := tea.NewProgram(&model, tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				return fmt.Errorf("TUI 运行失败: %w", err)
			}
			return nil
		},
	}
	return cmd
}

func init() {
	rootCmd.AddCommand(NewCmdTui())
}
