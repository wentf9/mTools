/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"example.com/MikuTools/utils"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mtool [command] [flags]",
	Short: "mtool(Miku Tools)是一个命令行工具集,用于日常运维和开发工作",
	Long: `mtool(Miku Tools)是一个命令行工具集,
提供了多种实用的命令行工具,旨在提高日常运维和开发工作的效率。
它包括对多台主机执行命令、批量处理文件、网络工具等功能。
使用mtool可以简化复杂的操作流程,节省时间和精力。`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		versionFlag, _ := cmd.Flags().GetBool("version")
		if versionFlag {
			println("mtool(Miku Tools) version 2025.08.22")
			os.Exit(0)
		}
		cmd.Help() // 显示帮助信息
		os.Exit(0)
	},
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		debugFlag, _ := cmd.Flags().GetBool("debug")
		if debugFlag {
			// 开启调试模式
			// 这里可以设置日志级别或其他调试相关的配置
			utils.Logger.SetLogLevel("debug")
			println("调试模式已开启")
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.demo.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.Flags().BoolP("version", "v", false, "显示版本信息")
	rootCmd.PersistentFlags().Bool("debug", false, "开启调试模式")
}
