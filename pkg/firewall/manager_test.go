package firewall

import (
	"context"
	"fmt"
	"testing"
)

func TestGetFirewallByName(t *testing.T) {
	exec := newMockExecutor()

	tests := []struct {
		input    string
		wantName string
	}{
		{"ufw", "ufw"},
		{"UFW", "ufw"},
		{"firewalld", "firewalld"},
		{"Firewalld", "firewalld"},
		{"iptables", "iptables"},
		{"IPTABLES", "iptables"},
		{"nftables", "nftables"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			fw, err := GetFirewallByName(tt.input, exec)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fw.Name() != tt.wantName {
				t.Errorf("Name() = %q, want %q", fw.Name(), tt.wantName)
			}
		})
	}
}

func TestGetFirewallByName_Unsupported(t *testing.T) {
	exec := newMockExecutor()

	unsupported := []string{"pf", "windows-firewall", ""}
	for _, name := range unsupported {
		t.Run(name, func(t *testing.T) {
			_, err := GetFirewallByName(name, exec)
			if err == nil {
				t.Errorf("expected error for unsupported firewall %q", name)
			}
		})
	}
}

func TestDetectFirewall_Firewalld(t *testing.T) {
	exec := newMockExecutor()
	exec.responses["command -v firewall-cmd"] = "/usr/bin/firewall-cmd"

	fw, err := DetectFirewall(context.Background(), exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fw.Name() != "firewalld" {
		t.Errorf("detected %q, want 'firewalld'", fw.Name())
	}
}

func TestDetectFirewall_Ufw(t *testing.T) {
	exec := newMockExecutor()
	exec.errors["command -v firewall-cmd"] = fmt.Errorf("not found")
	exec.responses["command -v ufw"] = "/usr/sbin/ufw"

	fw, err := DetectFirewall(context.Background(), exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fw.Name() != "ufw" {
		t.Errorf("detected %q, want 'ufw'", fw.Name())
	}
}

func TestDetectFirewall_Nftables(t *testing.T) {
	exec := newMockExecutor()
	exec.errors["command -v firewall-cmd"] = fmt.Errorf("not found")
	exec.errors["command -v ufw"] = fmt.Errorf("not found")
	exec.responses["command -v nft"] = "/usr/sbin/nft"

	fw, err := DetectFirewall(context.Background(), exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fw.Name() != "nftables" {
		t.Errorf("detected %q, want 'nftables'", fw.Name())
	}
}

func TestDetectFirewall_Iptables(t *testing.T) {
	exec := newMockExecutor()
	exec.errors["command -v firewall-cmd"] = fmt.Errorf("not found")
	exec.errors["command -v ufw"] = fmt.Errorf("not found")
	exec.errors["command -v nft"] = fmt.Errorf("not found")
	exec.responses["command -v iptables"] = "/usr/sbin/iptables"

	fw, err := DetectFirewall(context.Background(), exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fw.Name() != "iptables" {
		t.Errorf("detected %q, want 'iptables'", fw.Name())
	}
}

func TestDetectFirewall_NoFirewall(t *testing.T) {
	exec := newMockExecutor()
	exec.errors["command -v firewall-cmd"] = fmt.Errorf("not found")
	exec.errors["command -v ufw"] = fmt.Errorf("not found")
	exec.errors["command -v nft"] = fmt.Errorf("not found")
	exec.errors["command -v iptables"] = fmt.Errorf("not found")

	_, err := DetectFirewall(context.Background(), exec)
	if err == nil {
		t.Error("expected error when no firewall is detected")
	}
}
