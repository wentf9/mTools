package config

import (
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

// Provider 提供了基础的配置查询和管理功能
type Provider struct {
	cfg         *Configuration
	lookupIndex *concurrent.Map[string, string]
}

// NewProvider 创建一个新的配置提供者实例
func NewProvider(cfg *Configuration) ConfigProvider {
	provider := Provider{
		cfg:         cfg,
		lookupIndex: concurrent.NewMap[string, string](concurrent.HashString),
	}
	provider.init()
	return provider
}

// Add 将主机及其所有标识符加入索引
func (cp Provider) add(nodeID string) {
	node, ok := cp.GetNode(nodeID)
	if !ok {
		return
	}
	identity, ok := cp.GetIdentity(nodeID)
	if !ok {
		return
	}
	host, ok := cp.GetHost(nodeID)
	if !ok {
		return
	}
	cp.lookupIndex.Set(nodeID, nodeID)
	user := identity.User
	if user != "" {
		cp.lookupIndex.Set(fmt.Sprintf("%s@%s:%d", user, host.Address, host.Port), nodeID)
		for _, addr := range host.Alias {
			if addr == "" {
				continue
			}
			cp.lookupIndex.Set(fmt.Sprintf("%s@%s:%d", user, addr, host.Port), nodeID)
		}
	}
	for _, alias := range node.Alias {
		if alias == "" {
			continue
		}
		cp.lookupIndex.Set(alias, nodeID)
	}
}

// Find 匹配用户输入
func (cp Provider) Find(input string) string {
	// 1. 直接匹配
	if nodeID, ok := cp.lookupIndex.Get(input); ok {
		return nodeID
	}
	return ""
}

func (cp Provider) GetNode(nodeID string) (models.Node, bool) {
	return cp.cfg.Nodes.Get(nodeID)
}

func (cp Provider) GetHost(nodeID string) (models.Host, bool) {
	if node, ok := cp.cfg.Nodes.Get(nodeID); ok {
		return cp.cfg.Hosts.Get(node.HostRef)
	}
	return models.Host{}, false
}

func (cp Provider) GetIdentity(nodeID string) (models.Identity, bool) {
	if node, ok := cp.cfg.Nodes.Get(nodeID); ok {
		return cp.cfg.Identities.Get(node.IdentityRef)
	}
	return models.Identity{}, false
}

func (cp Provider) AddNode(nodeID string, node models.Node) {
	cp.cfg.Nodes.Set(nodeID, node)
	cp.add(nodeID)
}

func (cp Provider) AddHost(hostID string, host models.Host) {
	cp.cfg.Hosts.Set(hostID, host)
}

func (cp Provider) AddIdentity(identityID string, identity models.Identity) {
	cp.cfg.Identities.Set(identityID, identity)
}

func (cp Provider) DeleteNode(nodeID string) {
	if _, ok := cp.cfg.Nodes.Get(nodeID); ok {
		// 这里简单处理，暂时不删除引用的 Host 和 Identity，因为可能被多个 Node 引用
		// 但实际上目前的实现中，HostRef 和 IdentityRef 往往是唯一的
		cp.cfg.Nodes.Remove(nodeID)

		// 从索引中删除
		for _, key := range cp.lookupIndex.Keys() {
			if val, ok := cp.lookupIndex.Get(key); ok && val == nodeID {
				cp.lookupIndex.Remove(key)
			}
		}

		// 如果 Host 和 Identity 没有被其他 Node 引用，也可以考虑删除，但为了安全起见暂时保留
		// 或者根据业务逻辑决定是否级联删除
	}
}

func (cp Provider) ListNodes() map[string]models.Node {
	nodes := make(map[string]models.Node)
	for _, k := range cp.cfg.Nodes.Keys() {
		if v, ok := cp.cfg.Nodes.Get(k); ok {
			nodes[k] = v
		}
	}
	return nodes
}

func (cp Provider) GetNodesByTag(tag string) map[string]models.Node {
	result := make(map[string]models.Node)
	for _, nodeID := range cp.cfg.Nodes.Keys() {
		node, _ := cp.cfg.Nodes.Get(nodeID)
		if slices.Contains(node.Tags, tag) {
			result[nodeID] = node
		}
	}
	return result
}

func (cp Provider) ListIdentities() map[string]models.Identity {
	identities := make(map[string]models.Identity)
	for _, k := range cp.cfg.Identities.Keys() {
		if v, ok := cp.cfg.Identities.Get(k); ok {
			identities[k] = v
		}
	}
	return identities
}

func (cp Provider) DeleteIdentity(name string) {
	cp.cfg.Identities.Remove(name)
}

func (cp Provider) init() {
	for _, nodeID := range cp.cfg.Nodes.Keys() {
		cp.add(nodeID)
	}
}
