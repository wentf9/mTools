package cmd

import (
	"os"

	"example.com/MikuTools/cmd/host"
	"example.com/MikuTools/cmd/version"
	utils "example.com/MikuTools/pkg/logger"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "mtool [command] [flags]",
	Short: "mtool(Miku Tools)是一个命令行工具集,用于日常运维和开发工作",
	Long: `mtool(Miku Tools)是一个命令行工具集,
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
		debugFlag, _ := cmd.Flags().GetBool("debug")
		if debugFlag {
			utils.SetLogLevel("debug")
			utils.Logger.Debug("调试模式已开启")
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
	rootCmd.PersistentFlags().Bool("debug", false, "开启调试模式")

	// 注册子命令
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(host.NewCmdInventory())
}
