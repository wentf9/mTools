/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"net"
	"time"

	ping "github.com/prometheus-community/pro-bing"
	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

// pingCmd represents the ping command
var pingCmd = &cobra.Command{
	Use:   "ping <ip> [port]",
	Short: i18n.T("ping_short"),
	Long:  i18n.T("ping_long"),
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := args[0]

		if resolve, err := net.ResolveIPAddr("ip", ip); err != nil {
			return fmt.Errorf("提供的主机名无法解析为ip地址: %w", err)
		} else {
			logger.PrintInfo(i18n.Tf("ping_resolve_info", map[string]any{"Host": args[0], "IP": resolve.String()}))
			ip = resolve.String()
		}

		if len(args) == 2 {
			port := args[1]
			address := net.JoinHostPort(ip, port)
			logger.PrintInfo(i18n.Tf("ping_tcp_testing", map[string]any{"Address": address}))

			conn, err := net.DialTimeout("tcp", address, 5*time.Second)
			if err != nil {
				logger.PrintError(i18n.Tf("ping_port_closed", map[string]any{"IP": ip, "Port": port, "Error": err}))
				return nil
			}
			_ = conn.Close()
			logger.PrintSuccess(i18n.Tf("ping_port_open", map[string]any{"IP": ip, "Port": port}))
			return nil
		}

		logger.PrintInfo(i18n.Tf("ping_icmp_start", map[string]any{"IP": ip}))
		pinger, err := ping.NewPinger(ip)
		if err != nil {
			return fmt.Errorf("创建pinger失败: %w", err)
		}

		// 注意: 在 Linux/macOS 上，执行ICMP raw socket需要root权限。
		pinger.SetPrivileged(true)
		pinger.Count = 4
		pinger.Interval = time.Second
		pinger.Timeout = 4 * time.Second

		pinger.OnFinish = func(stats *ping.Statistics) {
			logger.PrintInfo(i18n.Tf("ping_stats_header", map[string]any{"Addr": stats.Addr}))
			logger.PrintInfo(i18n.Tf("ping_stats_packets", map[string]any{
				"Sent": stats.PacketsSent, "Recv": stats.PacketsRecv, "Loss": stats.PacketLoss,
			}))
			logger.PrintInfo(i18n.Tf("ping_stats_rtt", map[string]any{
				"Min": stats.MinRtt, "Avg": stats.AvgRtt, "Max": stats.MaxRtt, "StdDev": stats.StdDevRtt,
			}))
		}

		return pinger.Run() // 此处会阻塞直到ping结束
	},
}

func init() {
	rootCmd.AddCommand(pingCmd)
}
