package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Store interface {
	Load() (*Configuration, error)
	Save(cfg *Configuration) error
}

type defaultStore struct {
	Path string
	Key  []byte // 用于加解密配置文件中的敏感字段
}

func (s *defaultStore) Load() (*Configuration, error) {
	// 1. 读取文件
	// 2. yaml.Unmarshal
	// 3. 遍历 Identities，解密 Password/Passphrase 字段
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, err
	}
	var config Configuration
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func (s *defaultStore) Save(cfg *Configuration) error {
	// 1. 遍历 Identities，加密敏感字段
	// 2. yaml.Marshal
	// 3. 写入文件
	return nil
}

func NewDefaultStore(path string, key []byte) Store {
	return &defaultStore{
		Path: path,
		Key:  key,
	}
}
