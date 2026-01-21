package config

import (
	"example.com/MikuTools/pkg/models"
)

// Configuration 对应 yaml 文件的顶层结构
type Configuration struct {
	Identities map[string]models.Identity `yaml:"identities"`
	Hosts      map[string]models.Host     `yaml:"hosts"`
	Nodes      map[string]models.Node     `yaml:"nodes"`
}
