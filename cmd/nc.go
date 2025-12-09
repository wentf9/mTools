package cmd

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"example.com/MikuTools/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var ncCmd = &cobra.Command{
	Use:   "nc",
	Short: "网络工具,提供linux中nc命令的部分功能",
	Long: `网络工具,提供linux中nc命令的部分功能
	用法：
	mtool nc -l <port>
	监听指定的端口并输出所有请求内容,linux非root用户无法监听1024以内的端口
	mtool nc <ip> <port>
	连接到指定的ip和端口,并将标准输入内容发送到目标地址,请结合管道或重定向使用`,
	Example: `  mtool nc -l 8080
  mtool nc <ip> <port>`,
	Args: func(cmd *cobra.Command, args []string) error {
		port, err := cmd.Flags().GetUint16("listen")
		if err == nil && port != 0 {
			return nil
		}
		if len(args) != 2 {
			return fmt.Errorf("需要指定ip和端口,或者使用-l参数监听端口")
		}
		if net.ParseIP(args[0]) == nil {
			return fmt.Errorf("无效的IP地址: %s", args[0])
		}
		if port := utils.ParsePort(args[1]); port == 0 {
			return fmt.Errorf("无效的端口号: %s", args[1])
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		port, err := cmd.Flags().GetUint16("listen")
		udp, _ := cmd.Flags().GetBool("udp")
		var network string
		if udp {
			network = "udp"
		} else {
			network = "tcp"
		}
		if err == nil && port != 0 {

			listener, err := net.Listen(network, fmt.Sprintf(":%d", port))
			if err != nil {
				return fmt.Errorf("无法监听端口 %d: %w", port, err)
			}
			defer listener.Close()
			fmt.Fprintf(os.Stderr, "正在监听端口 %d...\n", port)
			conn, err := listener.Accept()
			if err != nil {
				return fmt.Errorf("接受连接失败: %w", err)
			}
			err = handleConnection(conn)
			if err != nil {
				return fmt.Errorf("处理连接失败: %w", err)
			}
			return nil
		}
		// 连接到目标 TCP 地址
		addr := net.JoinHostPort(args[0], args[1])
		conn, err := net.DialTimeout(network, addr, time.Second*10)
		if err != nil {
			return fmt.Errorf("failed to connect to %s: %v", addr, err)
		}
		fmt.Fprintf(os.Stderr, "已连接到 %s\n", addr)
		defer conn.Close()
		if term.IsTerminal(0) {
			utils.Logger.Debug("检测到标准输入是交互式终端")
			fmt.Fprintf(os.Stderr, "警告: 你正在交互式终端中运行此命令,将不会发送数据,建议通过管道或重定向将数据传输到此命令\n")
			return nil
		}
		reader := bufio.NewReader(os.Stdin)
		buffer := make([]byte, 1024*1024*10) // 10MB 缓冲区
		for {
			n, err := reader.Read(buffer)
			if n > 0 {
				utils.Logger.Debug(fmt.Sprintf("读取到 %d 字节数据", n))
				_, err := conn.Write(buffer[:n])
				if err != nil {
					return fmt.Errorf("写入连接失败: %w", err)
				}
			}
			if err != nil {
				if err == io.EOF {
					utils.Logger.Debug("标准输入读取到EOF,结束发送")
					break
				}
				return fmt.Errorf("读取输入失败: %w", err)
			}
		}
		return nil
	},
}

func handleConnection(conn net.Conn) error {
	defer conn.Close()

	// 获取客户端地址
	clientAddr := conn.RemoteAddr().String()
	fmt.Fprintf(os.Stderr, "新连接来自: %s\n", clientAddr)
	writer := bufio.NewWriter(os.Stdout)
	// 使用 bufio.Reader 读取数据（支持按行或批量读）
	reader := bufio.NewReader(conn)
	fmt.Fprintf(os.Stderr, "来自 %s 的请求内容:\n", clientAddr)
	buffer := make([]byte, 1024*1024*10) // 10MB 缓冲区
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			requestData := buffer[:n]
			_, err := writer.Write(requestData)
			if err != nil {
				return fmt.Errorf("写入输出失败: %w", err)
			}
			writer.Flush()
		}
		if err != nil {
			// 客户端断开或读取出错
			if err == io.EOF {
				fmt.Fprintf(os.Stderr, "连接 %s 关闭\n", clientAddr)
				return nil
			}
			return fmt.Errorf("连接 %s 出错: %w", clientAddr, err)
		}
	}
}

func init() {
	rootCmd.AddCommand(ncCmd)
	ncCmd.PersistentFlags().Uint16P("listen", "l", 0, "需要监听的端口,linux非root用户无法监听1024以内的端口")
	ncCmd.PersistentFlags().BoolP("udp", "u", false, "使用UDP协议,默认tcp")
}
