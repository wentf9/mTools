package cmd

import (
	"testing"
)

func TestResolvePathInfo(t *testing.T) {
	o := NewScpOptions()
	o.Host = "default_host"
	o.User = "default_user"
	o.Port = 2222

	tests := []struct {
		name     string
		path     PathInfo
		wantHost string
		wantUser string
		wantPort uint16
		wantErr  bool
	}{
		{"full override", PathInfo{Host: "h1", User: "u1", Port: 22}, "h1", "u1", 22, false},
		{"partial flag fallback", PathInfo{}, "default_host", "default_user", 2222, false},
		{"empty host error", PathInfo{}, "", "", 0, true},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if i == 2 {
				// clear default_host to trigger error
				o.Host = ""
			}
			h, u, p, err := o.resolvePathInfo(tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
			if !tt.wantErr {
				if h != tt.wantHost || u != tt.wantUser || p != tt.wantPort {
					t.Errorf("expected %v@%v:%v, got %v@%v:%v", tt.wantUser, tt.wantHost, tt.wantPort, u, h, p)
				}
			}
		})
	}
}
