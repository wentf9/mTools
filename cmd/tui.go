package cmd

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/tui"
)

func NewCmdTui() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "启动终端版主机管理面板",
		Long:  "启动一个全屏的高级终端用户界面 (TUI)，用于浏览、过滤、连接以及管理主机配置。",
		RunE: func(cmd *cobra.Command, args []string) error {
			configStore := config.NewDefaultStore(utils.GetConfigFilePath())
			cfg, err := configStore.Load()
			if err != nil {
				return fmt.Errorf("加载配置文件失败: %w", err)
			}
			provider := config.NewProvider(cfg)

			p := tea.NewProgram(tui.NewModel(provider, configStore), tea.WithAltScreen())
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
