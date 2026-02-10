package config

import (
	"os"
	"sync"

	"example.com/MikuTools/pkg/crypto"
	"example.com/MikuTools/pkg/models"
	"example.com/MikuTools/pkg/utils/concurrent"
	"example.com/MikuTools/pkg/utils/file"
	"gopkg.in/yaml.v3"
)

type Store interface {
	Load() (*Configuration, error)
	Save(cfg *Configuration) error
}

type defaultStore struct {
	Path    string
	KeyPath string // 用于加解密配置文件中的敏感字段
	mu      sync.Mutex
}

func (s *defaultStore) Load() (*Configuration, error) {
	config := Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	// 1. 读取文件
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return &config, nil
	}
	// 2. yaml.Unmarshal
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	// 初始化 Crypter
	key, err := crypto.LoadOrGenerateKey(s.KeyPath)
	if err != nil {
		return nil, err
	}
	crypter, err := crypto.NewCrypter(key)
	if err != nil {
		return nil, err
	}
	// 3. 遍历 Identities，解密 Password/Passphrase 字段
	for _, name := range config.Identities.Keys() {
		identity, _ := config.Identities.Get(name)
		// 处理 Password 字段
		if identity.Password != "" && crypto.IsEncrypted(identity.Password) {
			plain, err := crypter.Decrypt(identity.Password)
			if err != nil {
				// 记录日志或报错
				continue
			}
			identity.Password = plain
		}

		// 处理 Key Passphrase 字段
		if identity.Passphrase != "" && crypto.IsEncrypted(identity.Passphrase) {
			plain, err := crypter.Decrypt(identity.Passphrase)
			if err != nil {
				continue
			}
			identity.Passphrase = plain
		}
		config.Identities.Set(name, identity)
	}
	return &config, nil
}

func (s *defaultStore) Save(cfg *Configuration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 初始化 Crypter
	key, err := crypto.LoadOrGenerateKey(s.KeyPath)
	if err != nil {
		return err
	}
	crypter, err := crypto.NewCrypter(key)
	if err != nil {
		return err
	}
	// 1. 遍历 Identities，加密敏感字段
	for _, name := range cfg.Identities.Keys() {
		identity, _ := cfg.Identities.Get(name)
		// 处理 Password 字段
		if identity.Password != "" && !crypto.IsEncrypted(identity.Password) {
			enc, err := crypter.Encrypt(identity.Password)
			if err != nil {
				// 记录日志或报错
				continue
			}
			identity.Password = enc
		}

		// 处理 Key Passphrase 字段
		if identity.Passphrase != "" && !crypto.IsEncrypted(identity.Passphrase) {
			enc, err := crypter.Encrypt(identity.Passphrase)
			if err != nil {
				continue
			}
			identity.Passphrase = enc
		}
		cfg.Identities.Set(name, identity)
	}
	// 2. yaml.Marshal
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	// 3. 写入文件
	return file.CreateFileRecursive(s.Path, data, 0600)
}

func NewDefaultStore(path string, keyPath string) Store {
	return &defaultStore{
		Path:    path,
		KeyPath: keyPath,
	}
}
