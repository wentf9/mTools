package host

import (
	"reflect"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestApplyNodeUpdates(t *testing.T) {
	host := &models.Host{Address: "old_ip", Port: 22}
	identity := &models.Identity{User: "old_user"}
	node := &models.Node{Alias: []string{"old_alias"}}

	cmd := &cobra.Command{}
	cmd.Flags().StringSlice("alias", []string{}, "")
	cmd.Flags().String("jump", "", "")

	// Test 1: update address, port, user
	flags := &editFlags{
		address: "new_ip",
		port:    2222,
		user:    "new_user",
	}

	updated, nameChanged := applyNodeUpdates(cmd, host, identity, node, flags)
	if !updated || !nameChanged {
		t.Errorf("expected updated/nameChanged = true, got %v/%v", updated, nameChanged)
	}
	if host.Address != "new_ip" || host.Port != 2222 || identity.User != "new_user" {
		t.Errorf("Test 1 fields did not update correctly")
	}

	// Test 2: Set flag manually for alias
	flags2 := &editFlags{
		alias: []string{"new_alias"},
	}
	_ = cmd.Flags().Set("alias", "new_alias")
	updated, nameChanged = applyNodeUpdates(cmd, host, identity, node, flags2)
	if !updated || nameChanged {
		t.Errorf("expected updated=true, nameChanged=false, got %v/%v", updated, nameChanged)
	}
	if !reflect.DeepEqual(node.Alias, []string{"new_alias"}) {
		t.Errorf("alias did not update to new_alias")
	}

	// Test 3: Password change
	flags3 := &editFlags{
		password: "new_password",
	}
	updated, nameChanged = applyNodeUpdates(cmd, host, identity, node, flags3)
	if !updated || nameChanged {
		t.Errorf("expected updated=true, nameChanged=false, got %v/%v", updated, nameChanged)
	}
	if identity.Password != "new_password" || identity.AuthType != "password" {
		t.Errorf("Test 3 fields did not update correctly")
	}
}
