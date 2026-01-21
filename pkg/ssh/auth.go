package ssh

import (
	"os"

	"golang.org/x/crypto/ssh"
)

// AuthMethod 定义获取 SSH 认证方法的接口
type AuthMethod interface {
	GetMethod() (ssh.AuthMethod, error)
}

// PasswordAuth 实现密码认证
type PasswordAuth struct {
	Password string
}

func (p *PasswordAuth) GetMethod() (ssh.AuthMethod, error) {
	return ssh.Password(p.Password), nil
}

// KeyAuth 实现私钥认证
type KeyAuth struct {
	Path       string
	Passphrase string
}

func (k *KeyAuth) GetMethod() (ssh.AuthMethod, error) {
	// 读取文件、解析私钥的逻辑...
	keyData, err := os.ReadFile(k.Path)
	if err != nil {
		return nil, err
	}
	var signer ssh.Signer
	if k.Passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(k.Passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(keyData)
	}
	return ssh.PublicKeys(signer), nil
}
