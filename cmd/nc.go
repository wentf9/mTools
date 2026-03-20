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

func newCmdNc() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nc",
		Short: i18n.T("nc_short"),
		Long:  i18n.T("nc_long"),
		Example: `  xops nc -l 8080
  xops nc <ip> <port>`,
		Args: ncArgsValidator,
		RunE: ncRunE,
	}

	cmd.PersistentFlags().Uint16P("listen", "l", 0, i18n.T("flag_nc_listen"))
	cmd.PersistentFlags().BoolP("udp", "u", false, i18n.T("flag_nc_udp"))

	return cmd
}

func ncArgsValidator(cmd *cobra.Command, args []string) error {
	port, err := cmd.Flags().GetUint16("listen")
	if err == nil && port != 0 {
		return nil
	}
	if len(args) != 2 {
		return fmt.Errorf("%s", i18n.T("nc_err_args_missing"))
	}
	if net.ParseIP(args[0]) == nil {
		return fmt.Errorf("%s", i18n.Tf("nc_err_invalid_ip", map[string]any{"IP": args[0]}))
	}
	if port := cmdutils.ParsePort(args[1]); port == 0 {
		return fmt.Errorf("%s", i18n.Tf("nc_err_invalid_port", map[string]any{"Port": args[1]}))
	}
	return nil
}

func ncRunE(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetUint16("listen")
	udp, _ := cmd.Flags().GetBool("udp")

	network := "tcp"
	if udp {
		network = "udp"
	}

	if port != 0 {
		return ncListenMode(port, network)
	}
	return ncConnectMode(args, network)
}

func ncListenMode(port uint16, network string) error {
	listener, err := net.Listen(network, fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.Tf("nc_err_listen", map[string]any{"Port": port}), err)
	}
	defer func() { _ = listener.Close() }()

	_, _ = fmt.Fprint(os.Stderr, i18n.Tf("nc_listening", map[string]any{"Port": port}))
	conn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("nc_err_accept"), err)
	}

	if err := handleConnection(conn); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("nc_err_handle"), err)
	}
	return nil
}

func ncConnectMode(args []string, network string) error {
	addr := net.JoinHostPort(args[0], args[1])
	conn, err := net.DialTimeout(network, addr, time.Second*10)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.Tf("nc_err_connect", map[string]any{"Addr": addr}), err)
	}
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprint(os.Stderr, i18n.Tf("nc_connected", map[string]any{"Addr": addr}))

	if term.IsTerminal(0) {
		_, _ = fmt.Fprint(os.Stderr, i18n.T("nc_interactive_warning"))
		return nil
	}

	return ncSendFromStdin(conn)
}

func ncSendFromStdin(conn net.Conn) error {
	reader := bufio.NewReader(os.Stdin)
	buffer := make([]byte, 1024*1024*10) // 10MB 缓冲区

	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if _, writeErr := conn.Write(buffer[:n]); writeErr != nil {
				return fmt.Errorf("%s: %w", i18n.T("nc_err_write_conn"), writeErr)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("%s: %w", i18n.T("nc_err_read_input"), err)
		}
	}
	return nil
}

func handleConnection(conn net.Conn) error {
	defer func() { _ = conn.Close() }()

	clientAddr := conn.RemoteAddr().String()
	_, _ = fmt.Fprint(os.Stderr, i18n.Tf("nc_new_connection", map[string]any{"Addr": clientAddr}))
	_, _ = fmt.Fprint(os.Stderr, i18n.Tf("nc_request_content", map[string]any{"Addr": clientAddr}))

	writer := bufio.NewWriter(os.Stdout)
	reader := bufio.NewReader(conn)
	buffer := make([]byte, 1024*1024*10) // 10MB 缓冲区

	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if _, writeErr := writer.Write(buffer[:n]); writeErr != nil {
				return fmt.Errorf("%s: %w", i18n.T("nc_err_write_out"), writeErr)
			}
			_ = writer.Flush()
		}
		if err != nil {
			if err == io.EOF {
				_, _ = fmt.Fprint(os.Stderr, i18n.Tf("nc_connection_closed", map[string]any{"Addr": clientAddr}))
				return nil
			}
			return fmt.Errorf("%s: %w", i18n.Tf("nc_err_conn_error", map[string]any{"Addr": clientAddr}), err)
		}
	}
}
