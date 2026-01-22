package config

import (
	"errors"
	"fmt"

	"example.com/MikuTools/pkg/models"
	"example.com/MikuTools/pkg/utils/concurrent"
)

type NodeFinder interface {
	// Add 将节点(用户名@地址:端口 / 别名 / ID)加入索引
	Add(nodeId string, h *models.Node)
	// Find 匹配用户输入(用户名@地址:端口 / 别名 / ID)
	Find(input string) (*models.Node, error)
}

type finder struct {
	cfg         *Configuration
	nodes       *concurrent.Map[string, *models.Node]
	lookupIndex *concurrent.Map[string, string]
}

// Add 将主机及其所有标识符加入索引
func (f *finder) Add(nodeId string, n *models.Node) {
	identity, ok := f.cfg.Identities[n.IdentityRef]
	if !ok {
		return
	}
	host, ok := f.cfg.Hosts[n.HostRef]
	if !ok {
		return
	}
	f.nodes.Set(nodeId, n)
	f.lookupIndex.Set(nodeId, nodeId)
	user := identity.User
	if user != "" {
		f.lookupIndex.Set(fmt.Sprintf("%s@%s:%d", user, host.Address, host.Port), nodeId)
		for _, addr := range host.Alias {
			if addr == "" {
				continue
			}
			f.lookupIndex.Set(fmt.Sprintf("%s@%s:%d", user, addr, host.Port), nodeId)
		}
	}
	for _, alias := range n.Alias {
		if alias == "" {
			continue
		}
		f.lookupIndex.Set(alias, nodeId)
	}
}

// Find 匹配用户输入
func (f *finder) Find(input string) (*models.Node, error) {
	// 1. 直接匹配
	if nodeId, ok := f.lookupIndex.Get(input); ok {
		if node, ok := f.nodes.Get(nodeId); ok {
			return node, nil
		}
		return nil, errors.New("node in index but not found for input: " + input)
	}
	return nil, errors.New("node not found for input: " + input)
}

// NewNodeFinder 创建NodeFinder实例
func NewNodeFinder(cfg *Configuration) *finder {
	return &finder{
		cfg:         cfg,
		nodes:       concurrent.NewMap[string, *models.Node](concurrent.HashString),
		lookupIndex: concurrent.NewMap[string, string](concurrent.HashString),
	}
}
