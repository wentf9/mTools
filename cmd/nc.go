package cmd

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
	cmdutils "github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"golang.org/x/term"
)

var ncCmd = &cobra.Command{
	Use:   "nc",
	Short: i18n.T("nc_short"),
	Long:  i18n.T("nc_long"),
	Example: `  xops nc -l 8080
  xops nc <ip> <port>`,
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
		if port := cmdutils.ParsePort(args[1]); port == 0 {
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
			defer func() { _ = listener.Close() }()
			_, _ = fmt.Fprint(os.Stderr, i18n.Tf("nc_listening", map[string]any{"Port": port}))
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
			return fmt.Errorf("failed to connect to %s: %w", addr, err)
		}
		_, _ = fmt.Fprint(os.Stderr, i18n.Tf("nc_connected", map[string]any{"Addr": addr}))
		defer func() { _ = conn.Close() }()
		if term.IsTerminal(0) {

			_, _ = fmt.Fprint(os.Stderr, i18n.T("nc_interactive_warning"))
			return nil
		}
		reader := bufio.NewReader(os.Stdin)
		buffer := make([]byte, 1024*1024*10) // 10MB 缓冲区
		for {
			n, err := reader.Read(buffer)
			if n > 0 {

				_, err := conn.Write(buffer[:n])
				if err != nil {
					return fmt.Errorf("写入连接失败: %w", err)
				}
			}
			if err != nil {
				if err == io.EOF {

					break
				}
				return fmt.Errorf("读取输入失败: %w", err)
			}
		}
		return nil
	},
}

func handleConnection(conn net.Conn) error {
	defer func() { _ = conn.Close() }()

	// 获取客户端地址
	clientAddr := conn.RemoteAddr().String()
	_, _ = fmt.Fprint(os.Stderr, i18n.Tf("nc_new_connection", map[string]any{"Addr": clientAddr}))
	writer := bufio.NewWriter(os.Stdout)
	// 使用 bufio.Reader 读取数据（支持按行或批量读）
	reader := bufio.NewReader(conn)
	_, _ = fmt.Fprint(os.Stderr, i18n.Tf("nc_request_content", map[string]any{"Addr": clientAddr}))
	buffer := make([]byte, 1024*1024*10) // 10MB 缓冲区
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			requestData := buffer[:n]
			_, err := writer.Write(requestData)
			if err != nil {
				return fmt.Errorf("写入输出失败: %w", err)
			}
			_ = writer.Flush()
		}
		if err != nil {
			// 客户端断开或读取出错
			if err == io.EOF {
				_, _ = fmt.Fprint(os.Stderr, i18n.Tf("nc_connection_closed", map[string]any{"Addr": clientAddr}))
				return nil
			}
			return fmt.Errorf("连接 %s 出错: %w", clientAddr, err)
		}
	}
}

func init() {
	rootCmd.AddCommand(ncCmd)
	ncCmd.PersistentFlags().Uint16P("listen", "l", 0, i18n.T("flag_nc_listen"))
	ncCmd.PersistentFlags().BoolP("udp", "u", false, i18n.T("flag_nc_udp"))
}
