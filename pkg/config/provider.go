package config

import (
	"fmt"

	"example.com/MikuTools/pkg/models"
	"example.com/MikuTools/pkg/utils/concurrent"
)

type Provider struct {
	cfg         *Configuration
	lookupIndex *concurrent.Map[string, string]
}

func NewProvider(cfg *Configuration) ConfigProvider {
	provider := Provider{
		cfg:         cfg,
		lookupIndex: concurrent.NewMap[string, string](concurrent.HashString),
	}
	provider.init()
	return provider
}

// Add 将主机及其所有标识符加入索引
func (cp Provider) add(nodeId string) {
	node, ok := cp.GetNode(nodeId)
	if !ok {
		return
	}
	identity, ok := cp.GetIdentity(nodeId)
	if !ok {
		return
	}
	host, ok := cp.GetHost(nodeId)
	if !ok {
		return
	}
	cp.lookupIndex.Set(nodeId, nodeId)
	user := identity.User
	if user != "" {
		cp.lookupIndex.Set(fmt.Sprintf("%s@%s:%d", user, host.Address, host.Port), nodeId)
		for _, addr := range host.Alias {
			if addr == "" {
				continue
			}
			cp.lookupIndex.Set(fmt.Sprintf("%s@%s:%d", user, addr, host.Port), nodeId)
		}
	}
	for _, alias := range node.Alias {
		if alias == "" {
			continue
		}
		cp.lookupIndex.Set(alias, nodeId)
	}
}

// Find 匹配用户输入
func (cp Provider) Find(input string) string {
	// 1. 直接匹配
	if nodeId, ok := cp.lookupIndex.Get(input); ok {
		return nodeId
	}
	return ""
}

func (cp Provider) GetNode(nodeId string) (models.Node, bool) {
	return cp.cfg.Nodes.Get(nodeId)
}

func (cp Provider) GetHost(nodeId string) (models.Host, bool) {
	if node, ok := cp.cfg.Nodes.Get(nodeId); ok {
		return cp.cfg.Hosts.Get(node.HostRef)
	}
	return models.Host{}, false
}

func (cp Provider) GetIdentity(nodeId string) (models.Identity, bool) {
	if node, ok := cp.cfg.Nodes.Get(nodeId); ok {
		return cp.cfg.Identities.Get(node.IdentityRef)
	}
	return models.Identity{}, false
}

func (cp Provider) AddNode(nodeId string, node models.Node) {
	cp.cfg.Nodes.Set(nodeId, node)
	cp.add(nodeId)
}

func (cp Provider) AddHost(hostId string, host models.Host) {
	cp.cfg.Hosts.Set(hostId, host)
}

func (cp Provider) AddIdentity(identityId string, identity models.Identity) {
	cp.cfg.Identities.Set(identityId, identity)
}

func (cp Provider) DeleteNode(nodeId string) {
	if _, ok := cp.cfg.Nodes.Get(nodeId); ok {
		// 这里简单处理，暂时不删除引用的 Host 和 Identity，因为可能被多个 Node 引用
		// 但实际上目前的实现中，HostRef 和 IdentityRef 往往是唯一的
		cp.cfg.Nodes.Remove(nodeId)

		// 从索引中删除
		for _, key := range cp.lookupIndex.Keys() {
			if val, ok := cp.lookupIndex.Get(key); ok && val == nodeId {
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

func (cp Provider) init() {
	for _, nodeId := range cp.cfg.Nodes.Keys() {
		cp.add(nodeId)
	}
}
