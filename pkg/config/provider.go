package config

import (
	"errors"

	"example.com/MikuTools/pkg/models"
)

type Provider struct {
	cfg    Configuration
	finder NodeFinder
}

func NewProvider(cfg Configuration) *Provider {
	provider := Provider{cfg: cfg, finder: NewNodeFinder(&cfg)}
	provider.init()
	return &provider
}

func (cp *Provider) GetNode(name string) (*models.Node, error) {
	if node, err := cp.finder.Find(name); err != nil {
		return nil, err
	} else {
		return node, nil
	}
}

func (cp *Provider) GetHost(name string) (*models.Host, error) {
	if host, ok := cp.cfg.Hosts[name]; ok {
		return &host, nil
	} else {
		return nil, errors.New("host not found for inpute: " + name)
	}
}

func (cp *Provider) GetIdentity(name string) (*models.Identity, error) {
	if identity, ok := cp.cfg.Identities[name]; ok {
		return &identity, nil
	} else {
		return nil, errors.New("identity not found for inpute: " + name)
	}
}

func (cp *Provider) init() {
	for nodeId, node := range cp.cfg.Nodes {
		cp.finder.Add(nodeId, &node)
	}
}
