package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/crypto"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func newTestStoreAndConfig(t *testing.T) (Store, *Configuration) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	keyPath := filepath.Join(dir, "config.key")

	store := NewDefaultStore(configPath, keyPath)

	cfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("h1", models.Host{Address: "192.168.1.1", Port: 22})
	cfg.Identities.Set("i1", models.Identity{
		User:     "root",
		Password: "s3cret",
		AuthType: "password",
	})
	cfg.Nodes.Set("n1", models.Node{
		HostRef:     "h1",
		IdentityRef: "i1",
	})

	return store, cfg
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	store, cfg := newTestStoreAndConfig(t)

	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// 验证 host
	h, ok := loaded.Hosts.Get("h1")
	if !ok {
		t.Fatal("host h1 not found after load")
	}
	if h.Address != "192.168.1.1" || h.Port != 22 {
		t.Errorf("host = %+v, want {Address: 192.168.1.1, Port: 22}", h)
	}

	// 验证 identity（密码应已解密）
	i, ok := loaded.Identities.Get("i1")
	if !ok {
		t.Fatal("identity i1 not found after load")
	}
	if i.Password != "s3cret" {
		t.Errorf("password = %q, want 's3cret' (should be decrypted)", i.Password)
	}

	// 验证 node
	n, ok := loaded.Nodes.Get("n1")
	if !ok {
		t.Fatal("node n1 not found after load")
	}
	if n.HostRef != "h1" || n.IdentityRef != "i1" {
		t.Errorf("node = %+v, want {HostRef: h1, IdentityRef: i1}", n)
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nonexistent.yaml")
	keyPath := filepath.Join(dir, "config.key")

	store := NewDefaultStore(configPath, keyPath)
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("Load of nonexistent file should not error: %v", err)
	}
	if cfg.Nodes.Count() != 0 {
		t.Error("expected empty config from nonexistent file")
	}
}

func TestSave_EncryptsPassword(t *testing.T) {
	store, cfg := newTestStoreAndConfig(t)
	s := store.(*defaultStore)

	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// 读取原始文件内容，验证密码不是明文
	data, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}
	content := string(data)

	if strings.Contains(content, "s3cret") {
		t.Error("config file contains plaintext password, expected encrypted")
	}
	if !strings.Contains(content, crypto.Prefix) {
		t.Error("config file should contain ENC: prefix for password")
	}
}

func TestSave_PreservesMemoryPlaintext(t *testing.T) {
	store, cfg := newTestStoreAndConfig(t)

	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// 保存后内存中应仍为明文
	i, _ := cfg.Identities.Get("i1")
	if i.Password != "s3cret" {
		t.Errorf("in-memory password = %q, want 's3cret' (should stay plaintext after save)", i.Password)
	}
}
