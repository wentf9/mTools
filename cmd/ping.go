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
)

// pingCmd represents the ping command
var pingCmd = &cobra.Command{
	Use:   "ping <ip> [port]",
	Short: "通过ICMP Ping主机或检查主机的TCP端口是否开放",
	Long: `该命令有两种工作模式:
1. ICMP Ping (1个参数):
   当只提供一个IP地址或主机名时,它会发送ICMP请求来测试网络连通性,
   类似于系统自带的ping工具。
   示例: mikuTools ping 8.8.8.8

2. TCP端口检查 (2个参数):
   当提供IP地址/主机名和端口号时,它会尝试建立TCP连接来判断端口是否开放。
   示例: mikuTools ping 8.8.8.8 53`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := args[0]

		// 情况2: 提供了IP和端口，进行TCP端口检查
		if len(args) == 2 {
			port := args[1]
			address := net.JoinHostPort(ip, port)
			fmt.Printf("正在测试到 %s 的TCP连接...\n", address)

			conn, err := net.DialTimeout("tcp", address, 5*time.Second)
			if err != nil {
				fmt.Printf("主机 %s 的端口 %s 已关闭或被过滤: %v\n", ip, port, err)
				return nil // 命令本身执行成功，所以不返回错误
			}
			conn.Close()
			fmt.Printf("主机 %s 的端口 %s 是开放的!\n", ip, port)
			return nil
		}

		// 情况1: 只提供了IP，进行ICMP ping
		fmt.Printf("正在通过ICMP Ping %s...\n", ip)
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
			fmt.Printf("\n--- %s 的 ping 统计信息 ---\n", stats.Addr)
			fmt.Printf("%d 个包已发送, %d 个包已接收, %v%% 包丢失\n",
				stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
			fmt.Printf("往返行程 最小/平均/最大/标准差 = %v/%v/%v/%v\n",
				stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
		}

		return pinger.Run() // 此处会阻塞直到ping结束
	},
}

func init() {
	rootCmd.AddCommand(pingCmd)
}
