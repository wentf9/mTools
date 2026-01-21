package ssh

import (
	"example.com/MikuTools/pkg/models"
	"golang.org/x/crypto/ssh"
)

type Client struct {
	sshClient *ssh.Client
	node      *models.Node
}

func NewClient(raw *ssh.Client, node *models.Node) *Client {
	return &Client{
		sshClient: raw,
		node:      node,
	}
}

// Close 关闭连接
func (c *Client) Close() error {
	return c.sshClient.Close()
}

// SSHClient 暴露底层的 ssh.Client (供高级操作使用，如 SCP)
func (c *Client) SSHClient() *ssh.Client {
	return c.sshClient
}

// Node 返回当前连接对应的节点配置
func (c *Client) Node() *models.Node {
	return c.node
}

// TODO: 在这里添加 Execute, Shell 等方法，并在这里处理 Sudo 逻辑
