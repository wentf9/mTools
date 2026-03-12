package mcpserver

import (
	"context"
	"fmt"

	"example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/mcpserver/guardrail"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func Serve(ctx context.Context) error {
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "mtools-mcp",
			Version: "v1.0.0",
		},
		&mcp.ServerOptions{
			Capabilities: &mcp.ServerCapabilities{
				Tools: &mcp.ToolCapabilities{ListChanged: true},
			},
		},
	)

	g := loadGuardrail()

	RegisterTools(server, g)

	transport := &mcp.StdioTransport{}
	if err := server.Run(ctx, transport); err != nil {
		return fmt.Errorf("MCP Server error: %v", err)
	}
	return nil
}

// loadGuardrail reads GuardrailConfig from the user config file.
// Falls back to defaults if config is absent or unreadable.
func loadGuardrail() *guardrail.Guardrail {
	_, _, cfg, err := utils.GetConfigStore()
	if err != nil || cfg == nil || cfg.Guardrail == nil {
		return guardrail.New(nil)
	}
	return guardrail.New(cfg.Guardrail)
}
