package mcpserver

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/pkg/mcpserver/guardrail"
)

// RegisterTools 统一注册各模块的 MCP 能力，并注入安全护栏
func RegisterTools(server *mcp.Server, g *guardrail.Guardrail) {
	RegisterSSH(server, g)
	RegisterSFTP(server, g)
	RegisterFS(server, g)
}
