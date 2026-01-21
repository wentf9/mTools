package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"example.com/MikuTools/pkg/models"
	"example.com/MikuTools/pkg/utils/concurrent"
	"golang.org/x/crypto/ssh"
)

// Connector 负责创建 SSH 连接
type Connector struct {
	Config ConfigProvider
	// 连接池：缓存 nodeName -> *ssh.Client
	mu      sync.Mutex
	clients *concurrent.Map[string, *ssh.Client]
}

// NewConnector 创建一个新的 Connector
func NewConnector(cfg ConfigProvider) *Connector {
	return &Connector{
		Config:  cfg,
		clients: concurrent.NewMap[string, *ssh.Client](concurrent.HashString),
	}
}

// Connect 根据节点名称建立 SSH 连接
// 自动处理跳板机逻辑：如果节点配置了 ProxyJump，会递归建立连接
func (c *Connector) Connect(ctx context.Context, nodeName string) (*Client, error) {
	cachedClient, ok := c.clients.Get(nodeName)
	if ok {
		// 可选：检查连接是否存活（发送一个非阻塞的 KeepAlive 请求）
		// 对于短生命周期的 CLI 工具，通常假设缓存的连接是可用的
		node, _ := c.Config.GetNode(nodeName) // 重新获取配置以防更新，或者缓存 wrapper
		return NewClient(cachedClient, node), nil
	}
	// 缓存未命中，开始建立新连接
	// 使用写锁防止并发重复连接
	c.mu.Lock()
	defer c.mu.Unlock()

	// 双重检查：在获取锁的过程中可能已经被别的协程连上了
	if cachedClient, ok := c.clients.Get(nodeName); ok {
		node, _ := c.Config.GetNode(nodeName)
		return NewClient(cachedClient, node), nil
	}

	// 1. 获取节点配置
	node, err := c.Config.GetNode(nodeName)
	if err != nil {
		return nil, fmt.Errorf("node not found '%s': %w", nodeName, err)
	}

	// 2. 获取关联的 Host 和 Identity 数据
	host, err := c.Config.GetHost(node.HostRef)
	if err != nil {
		return nil, fmt.Errorf("host ref '%s' not found for node '%s': %w", node.HostRef, nodeName, err)
	}
	identity, err := c.Config.GetIdentity(node.IdentityRef)
	if err != nil {
		return nil, fmt.Errorf("identity ref '%s' not found for node '%s': %w", node.IdentityRef, nodeName, err)
	}

	// 3. 确定网络拨号器 (Dialer)
	// 如果有 ProxyJump，递归连接跳板机，将其 SSH Client 封装为 Dialer
	var dialer Dialer = &net.Dialer{Timeout: 10 * time.Second} // 默认直连

	if node.ProxyJump != "" {
		// 递归：连接跳板机
		jumpNodeClient, err := c.Connect(ctx, node.ProxyJump)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to jump host '%s': %w", node.ProxyJump, err)
		}
		// 封装：使用跳板机的 SSH 通道作为 Dialer
		dialer = &SSHProxyDialer{Client: jumpNodeClient.sshClient}
	}

	// 4. 构建目标 SSH 配置 (认证信息)
	sshConfig, err := c.buildSSHConfig(identity)
	if err != nil {
		return nil, fmt.Errorf("failed to build ssh config for '%s': %w", nodeName, err)
	}

	// 5. 建立底层 TCP 连接 (通过 Dialer)
	targetAddr := fmt.Sprintf("%s:%d", host.Address, host.Port)
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial target '%s' (%s): %w", nodeName, targetAddr, err)
	}

	// 6. 建立 SSH 会话
	// 使用 NewClientConn 接管底层的 conn
	ncc, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, sshConfig)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake failed for '%s': %w", nodeName, err)
	}
	rawClient := ssh.NewClient(ncc, chans, reqs)
	c.clients.Set(nodeName, rawClient)
	// 7. 返回封装的 Client
	return NewClient(rawClient, node), nil
}

// CloseAll 关闭所有缓存的连接 (在程序退出前调用)
func (c *Connector) CloseAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clients.IterCb(func(name string, client *ssh.Client) bool {
		client.Close()
		return true
	})
	c.clients.Clear()
}

// buildSSHConfig 根据 Identity 模型构建 ssh.ClientConfig
func (c *Connector) buildSSHConfig(id *models.Identity) (*ssh.ClientConfig, error) {
	authMethods := []ssh.AuthMethod{}

	// 根据 AuthType 处理不同的认证方式
	switch id.AuthType {
	case "password":
		if id.Password == "" {
			return nil, fmt.Errorf("auth type is password but password is empty")
		}
		authMethods = append(authMethods, ssh.Password(id.Password))

	case "key":
		if id.KeyPath == "" {
			return nil, fmt.Errorf("auth type is key but key_path is empty")
		}
		// 读取私钥文件
		keyBytes, err := os.ReadFile(expandHomeDir(id.KeyPath))
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}

		var signer ssh.Signer
		if id.Passphrase != "" {
			// 有密码的私钥
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(id.Passphrase))
		} else {
			// 无密码的私钥
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))

	default:
		return nil, fmt.Errorf("unsupported auth type: %s", id.AuthType)
	}

	return &ssh.ClientConfig{
		User:            id.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: 生产环境应集成 known_hosts 检查
		Timeout:         15 * time.Second,
	}, nil
}

// expandHomeDir 简单的路径处理辅助函数
func expandHomeDir(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			return home + path[1:]
		}
	}
	return path
}
