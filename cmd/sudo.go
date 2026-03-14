package cmd

import (
	"context"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/executor"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

var (
	sudoPassword string
	sudoShell    bool
)

// sudoCmd represents the sudo command
var sudoCmd = &cobra.Command{
	Use:   "sudo [command]",
	Short: i18n.T("sudo_short"),
	Long:  i18n.T("sudo_long"),
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. 获取密码
		pwd := sudoPassword
		if pwd == "" {
			// 尝试从配置文件中联动
			pwd = utils.GetLocalSudoPassword()
		}
		if pwd == "" {

			p, err := utils.ReadPasswordFromTerminal(i18n.T("prompt_sudo_password"))
			if err == nil {
				pwd = p
			}
		}

		// 2. 初始化执行器
		exec := executor.NewLocalExecutor(pwd)

		// 3. 处理 -s 选项或直接执行命令
		if sudoShell || len(args) == 0 {
			// 如果指定了 -s 或者没有任何参数，则进入交互式 shell
			return exec.InteractiveWithSudo(context.Background(), args)
		}

		// 执行单条命令
		fullCmd := strings.Join(args, " ")
		output, err := exec.RunWithSudo(context.Background(), fullCmd)
		if err != nil {
			logger.PrintError(i18n.Tf("sudo_exec_failed", map[string]any{"Error": err}))
			return nil
		}
		// sudo 输出保持纯净，因为直接展示目标机回显
		logger.Print(output)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(sudoCmd)
	sudoCmd.Flags().StringVarP(&sudoPassword, "passwd", "p", "", i18n.T("flag_sudo_passwd"))
	sudoCmd.Flags().BoolVarP(&sudoShell, "shell", "s", false, i18n.T("flag_sudo_shell"))
}
