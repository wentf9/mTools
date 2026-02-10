package cmd

import (
	"context"
	"fmt"
	"strings"

	"example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/executor"
	"github.com/spf13/cobra"
)

var (
	sudoPassword string
	sudoShell    bool
)

// sudoCmd represents the sudo command
var sudoCmd = &cobra.Command{
	Use:   "sudo [command]",
	Short: "在本机sudo执行命令",
	Long: `在本机sudo执行命令，支持从配置文件中自动获取密码。
示例:
  mtool sudo "ss -tlpn"
  mtool sudo -s
  mtool sudo "firewall-cmd --list-all" -p mypassword`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. 获取密码
		pwd := sudoPassword
		if pwd == "" {
			// 尝试从配置文件中联动
			pwd = utils.GetLocalSudoPassword()
		}
		if pwd == "" {

			p, err := utils.ReadPasswordFromTerminal("请输入sudo密码(无密码请直接回车):")
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
			return err
		}
		fmt.Print(output)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(sudoCmd)
	sudoCmd.Flags().StringVarP(&sudoPassword, "passwd", "p", "", "本地 sudo 密码")
	sudoCmd.Flags().BoolVarP(&sudoShell, "shell", "s", false, "直接进入 root 环境 (类似 sudo -s)")
}
