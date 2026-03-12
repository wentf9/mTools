package mcpserver

import (
	"example.com/MikuTools/pkg/mcpserver/guardrail"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterTools 统一注册各模块的 MCP 能力，并注入安全护栏
func RegisterTools(server *mcp.Server, g *guardrail.Guardrail) {
	RegisterSSH(server, g)
	RegisterSFTP(server, g)
	RegisterFS(server, g)
}
