package cmd

import (
	"os"

	"github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/version"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "xops [command] [flags]",
	Short: "xops(XOps)是一个命令行工具集,用于日常运维和开发工作",
	Long: `xops(XOps)是一个命令行工具集,
提供了多种实用的命令行工具,旨在提高日常运维和开发工作的效率。`,
	Run: func(cmd *cobra.Command, args []string) {
		versionFlag, _ := cmd.Flags().GetBool("version")
		if versionFlag {
			version.PrintFullVersion()
			os.Exit(0)
		}
		cmd.Help()
		os.Exit(0)
	},
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logLevel, _ := cmd.Flags().GetString("log-level")
		debugFlag, _ := cmd.Flags().GetBool("debug")

		// 如果指明了 --debug，则强制覆盖 log-level 为 debug
		if debugFlag {
			logLevel = "debug"
		}

		logger.SetLogLevel(logLevel)
		if logLevel == "debug" {
			logger.Debug("调试模式已开启")
		}
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		version.PrintFullVersion()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("version", "v", false, "显示版本信息")
	rootCmd.PersistentFlags().String("log-level", "", "设置内部诊断日志级别 (debug, info, warn, error)")
	rootCmd.PersistentFlags().Bool("debug", false, "开启调试模式 (等同于 --log-level=debug)")

	// 注册子命令
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(host.NewCmdInventory())
}
