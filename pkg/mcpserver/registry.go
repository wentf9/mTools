package mcpserver

import "github.com/modelcontextprotocol/go-sdk/mcp"

// RegisterTools 统一注册各模块的 MCP 能力
func RegisterTools(server *mcp.Server) {
	RegisterSSH(server)
	RegisterSFTP(server)
	RegisterFS(server)
}
