package sftp

import (
	"fmt"

	"example.com/MikuTools/pkg/ssh" // 引用我们要复用的 ssh 包
	"github.com/pkg/sftp"
)

// Option 定义配置函数的类型
type Option func(*Client)

func WithConcurrentFiles(con int) Option {
	return func(c *Client) {
		if con > 0 {
			c.config.ConcurrentFiles = con
		}
	}
}

func WithThreadsPerFile(t int) Option {
	return func(c *Client) {
		if t > 0 {
			c.config.ConcurrentFiles = t
		}
	}
}

func WithChunkSize(size int) Option {
	return func(c *Client) {
		if size > 0 {
			c.config.ConcurrentFiles = size
		}
	}
}

// Client 包装了 sftp.Client，并持有底层的 ssh 连接引用
type Client struct {
	sftpClient *sftp.Client
	sshClient  *ssh.Client // 保留引用，方便获取 Node 信息或关闭连接
	config     TransferConfig
}

// New 基于现有的 SSH 连接创建一个 SFTP 客户端
// 这里复用了 pkg/ssh 中已经建立好的连接 (包括跳板机隧道)
func NewClient(sshCli *ssh.Client, opts ...Option) (*Client, error) {
	// sftp.NewClient 会在 ssh 连接上打开一个新的 Subsystem
	client, err := sftp.NewClient(sshCli.SSHClient())
	if err != nil {
		return nil, fmt.Errorf("failed to create sftp subsystem: %w", err)
	}
	sftpCli := &Client{
		sftpClient: client,
		sshClient:  sshCli,
		config:     DefaultConfig(),
	}
	// 应用用户传入的配置
	for _, opt := range opts {
		opt(sftpCli)
	}
	return sftpCli, nil
}

// SFTPClient 返回底层的 *sftp.Client 对象，
// 允许调用者执行 rename, chmod, stat, symlink 等高级操作。
func (c *Client) SFTPClient() *sftp.Client {
	return c.sftpClient
}

// Close 关闭 SFTP 会话 (注意：这不会关闭底层的 SSH 连接，除非你希望这样)
func (c *Client) Close() error {
	return c.sftpClient.Close()
}

// Cwd 获取远程当前工作目录
func (c *Client) Cwd() (string, error) {
	return c.sftpClient.Getwd()
}

// JoinPath 辅助函数：处理远程路径拼接 (SFTP 协议强制使用 forward slash)
func (c *Client) JoinPath(elem ...string) string {
	return c.sftpClient.Join(elem...)
}
