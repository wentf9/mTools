package config

import (
	"example.com/MikuTools/pkg/models"
	"example.com/MikuTools/pkg/utils/concurrent"
)

// Configuration 对应 yaml 文件的顶层结构
type Configuration struct {
	Identities *concurrent.Map[string, models.Identity] `yaml:"identities"`
	Hosts      *concurrent.Map[string, models.Host]     `yaml:"hosts"`
	Nodes      *concurrent.Map[string, models.Node]     `yaml:"nodes"`
}

// ConfigProvider 定义 Connector 获取配置数据的接口
type ConfigProvider interface {
	GetNode(name string) (models.Node, bool)
	GetHost(name string) (models.Host, bool)
	GetIdentity(name string) (models.Identity, bool)
	AddHost(name string, host models.Host)
	AddIdentity(name string, identity models.Identity)
	AddNode(name string, node models.Node)
	DeleteNode(name string)
	ListNodes() map[string]models.Node
	GetNodesByTag(tag string) map[string]models.Node
	Find(input string) string
}
