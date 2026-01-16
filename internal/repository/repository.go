package repository

import (
	"net"

	"example.com/MikuTools/internal/model"
	"example.com/MikuTools/pkg/utils"
	cmap "example.com/MikuTools/pkg/utils/map"
)

type HostFinder struct {
	hosts       *cmap.ConcurrentMap[string, *model.Host]
	lookupIndex *cmap.ConcurrentMap[string, string]
}

// AddHost 将主机及其所有标识符加入索引
func (f *HostFinder) AddHost(h *model.Host) {
	f.hosts.Set(h.Alias, h)
	f.lookupIndex.Set(h.Alias, h.Alias)
	for _, host := range h.HostNames {
		if host == "" {
			continue
		}
		f.lookupIndex.Set(host, h.Alias)
	}
}

// Find 匹配用户输入
func (f *HostFinder) Find(input string) (*model.Host, bool) {
	if alias, ok := f.lookupIndex.Get(input); ok {
		return f.hosts.Get(alias)
	}
	// 2. 尝试作为 IP 规范化后匹配
	if ip := net.ParseIP(input); ip != nil {
		if alias, ok := f.lookupIndex.Get(ip.String()); ok {
			return f.hosts.Get(alias)
		}
	}
	return nil, false
}

// NewHostFinder 创建HostFinder实例
func NewHostFinder() *HostFinder {
	return &HostFinder{
		hosts:       cmap.NewConcurrentMap[string, *model.Host](utils.HashString),
		lookupIndex: cmap.NewConcurrentMap[string, string](utils.HashString),
	}
}
