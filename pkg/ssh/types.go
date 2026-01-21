package ssh

import (
	"context"
	"net"

	"example.com/MikuTools/pkg/models"
)

// ConfigProvider 定义 Connector 获取配置数据的接口
type ConfigProvider interface {
	GetNode(name string) (*models.Node, error)
	GetHost(name string) (*models.Host, error)
	GetIdentity(name string) (*models.Identity, error)
}

// Dialer 定义网络连接行为的接口
// 用于统一 "直连" 和 "通过 SSH 跳板机连接" 的行为
type Dialer interface {
	Dial(network, addr string) (net.Conn, error)
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}
