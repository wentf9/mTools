package cmd

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/mcpserver"
	"github.com/spf13/cobra"
)

func NewCmdMcp() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "启动 MCP (Model Context Protocol) 服务端",
		Long:  `以标准输入输出 (Stdio) 启动 MCP 服务端，供 Agent 调用。开启后所有常规业务输出与日志将会被屏蔽。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// MCP server 必须完全静默，避免污染 stdout json-rpc 流
			logger.SetLogLevel("none")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-sigCh
				cancel()
			}()

			err := mcpserver.Serve(ctx)
			if err != nil {
				if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "closing") {
					return nil
				}
				return err
			}
			return nil
		},
	}
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd
}

func init() {
	rootCmd.AddCommand(NewCmdMcp())
}
