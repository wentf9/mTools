package cmd

import (
	"github.com/wentf9/xops-cli/cmd/host"
	"github.com/spf13/cobra"
)

// loadHostCmd represents the loadHost command
var loadHostCmd = &cobra.Command{
	Use:   "loadHost [csv_file]",
	Short: "从CSV文件加载主机及凭据并验证保存 (inventory load 的快捷入口)",
	Long: `从CSV文件中加载主机、用户名和密码并保存到配置文件中。
该命令是 'inventory load' 的快捷方式。`,
	RunE: host.RunInventoryLoad,
}

func init() {
	loadHostCmd.Flags().StringVarP(&host.TemplateFile, "template", "T", "", "导出CSV导入模板到指定文件")
	loadHostCmd.Flags().StringVarP(&host.Tag, "tag", "t", "", "将导入的主机加入指定标签组")
	rootCmd.AddCommand(loadHostCmd)
}
