package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func Serve(ctx context.Context) error {
	// Create server
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

	// Register tools
	RegisterTools(server)

	// Run server using StdioTransport
	transport := &mcp.StdioTransport{}
	if err := server.Run(ctx, transport); err != nil {
		return fmt.Errorf("MCP Server error: %v", err)
	}
	return nil
}
