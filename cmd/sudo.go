package cmd

import (
	"github.com/spf13/cobra"
)

var password string

// dnsCmd represents the loadPwd command
var sudoCmd = &cobra.Command{
	Use:   "sudo [command] [-p password]",
	Short: "在本机sudo执行命令",
	Long: `在本机sudo执行命令
	示例:
	mtool sudo 'ss -tlpn'
	mtool sudo 'firewall-cmd --list-all' -p password`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func init() {
	rootCmd.AddCommand(sudoCmd)
	sudoCmd.Flags().StringVarP(&password, "passwd", "p", "", "SSH密码")
}
