package config

import (
	"os"
	"sync"

	"github.com/wentf9/xops-cli/pkg/crypto"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	"github.com/wentf9/xops-cli/pkg/utils/file"
	"gopkg.in/yaml.v3"
)

// Store 定义了配置存储和持久化的接口
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

	// 记录原始值以便在保存后恢复，防止内存中被加密后的数据污染
	originalPasswords := make(map[string]string)
	originalPassphrases := make(map[string]string)

	// 1. 遍历 Identities，加密敏感字段
	for _, name := range cfg.Identities.Keys() {
		identity, _ := cfg.Identities.Get(name)
		// 处理 Password 字段
		if identity.Password != "" && !crypto.IsEncrypted(identity.Password) {
			originalPasswords[name] = identity.Password
			enc, err := crypter.Encrypt(identity.Password)
			if err != nil {
				// 记录日志或报错
				continue
			}
			identity.Password = enc
		}

		// 处理 Key Passphrase 字段
		if identity.Passphrase != "" && !crypto.IsEncrypted(identity.Passphrase) {
			originalPassphrases[name] = identity.Passphrase
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

	// 序列化后立即恢复内存中的明文
	for name, plainPassword := range originalPasswords {
		if identity, ok := cfg.Identities.Get(name); ok {
			identity.Password = plainPassword
			cfg.Identities.Set(name, identity)
		}
	}
	for name, plainPassphrase := range originalPassphrases {
		if identity, ok := cfg.Identities.Get(name); ok {
			identity.Passphrase = plainPassphrase
			cfg.Identities.Set(name, identity)
		}
	}

	if err != nil {
		return err
	}
	// 3. 写入文件
	return file.CreateFileRecursive(s.Path, data, 0600)
}

// NewDefaultStore 创建一个默认的文件系统配置存储实例
func NewDefaultStore(path string, keyPath string) Store {
	return &defaultStore{
		Path:    path,
		KeyPath: keyPath,
	}
}
