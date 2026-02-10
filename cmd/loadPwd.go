package cmd

import (
	"context"
	"fmt"

	cmdutils "example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/config"
	"example.com/MikuTools/pkg/ssh"
	pkgutils "example.com/MikuTools/pkg/utils"
	"github.com/spf13/cobra"
)

// loadPwdCmd represents the loadPwd command
var loadPwdCmd = &cobra.Command{
	Use:   "loadPwd [csv_file]",
	Short: "从CSV文件加载密码并验证保存",
	Long: `从CSV文件中加载密码并保存到配置文件中。
会建立SSH连接验证密码的准确性。
CSV格式: IP,用户名,密码`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("期望一个参数 (CSV文件路径), 但提供了 %d 个", len(args))
		}
		csvFile := args[0]
		hosts, err := cmdutils.ReadCSVFile(csvFile)
		if err != nil {
			return fmt.Errorf("读取CSV文件失败: %v", err)
		}

		return runLoadPwd(hosts)
	},
}

func runLoadPwd(hosts []cmdutils.HostInfo) error {
	configPath, keyPath := cmdutils.GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("加载配置文件失败: %v", err)
	}
	provider := config.NewProvider(cfg)
	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	ctx := context.Background()
	wp := pkgutils.NewWorkerPool(uint(len(hosts)))

	o := NewExecOptions() // Use for getOrCreateNode helper logic if needed, but let's just do it here

	for _, host := range hosts {
		host := host
		wp.Execute(func() {
			nodeId, _, err := o.getOrCreateNode(provider, host)
			if err != nil {
				fmt.Printf("[%s] 错误: %v\n", host.IP, err)
				return
			}

			// 验证连接
			client, err := connector.Connect(ctx, nodeId)
			if err != nil {
				fmt.Printf("[%s] 验证失败: %v\n", host.IP, err)
				return
			}
			client.Close()

			fmt.Printf("[%s] 验证通过并已保存\n", host.IP)

		})
	}

	wp.Wait()
	return configStore.Save(cfg)
}

func init() {
	rootCmd.AddCommand(loadPwdCmd)
}
