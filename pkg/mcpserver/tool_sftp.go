package mcpserver

import (
	"context"
	"fmt"
	"io"
	"os"

	"example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/mcpserver/guardrail"
	"example.com/MikuTools/pkg/sftp"
	"example.com/MikuTools/pkg/ssh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type TransferFileInput struct {
	NodeID     string `json:"nodeId" jsonschema:"Node ID for the remote machine"`
	LocalPath  string `json:"localPath" jsonschema:"Absolute path to the local file or directory"`
	RemotePath string `json:"remotePath" jsonschema:"Absolute path to the remote file or directory"`
}

type TransferFileOutput struct {
	Status string `json:"status" jsonschema:"Operation status"`
}

const defaultReadLimit int64 = 50 * 1024 // 50KB default

type ReadFileInput struct {
	NodeID string `json:"nodeId" jsonschema:"Node ID for the remote machine"`
	Path   string `json:"path" jsonschema:"Absolute path to the remote file"`
	Offset int64  `json:"offset,omitempty" jsonschema:"Byte offset to start reading from"`
	Limit  int64  `json:"limit,omitempty" jsonschema:"Max bytes to read (default 50KB, max 100KB)"`
}

type ReadFileOutput struct {
	Content string `json:"content" jsonschema:"File content represented as string"`
	EOF     bool   `json:"eof" jsonschema:"True if end of file reached"`
	Size    int64  `json:"size" jsonschema:"Total size of the remote file"`
	Status  string `json:"status" jsonschema:"Operation status"`
}

func readFileHandler(ctx context.Context, req *mcp.CallToolRequest, input ReadFileInput) (*mcp.CallToolResult, ReadFileOutput, error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, ReadFileOutput{}, fmt.Errorf("nodeId and path are required")
	}

	limit := input.Limit
	if limit <= 0 {
		limit = defaultReadLimit
	}
	if limit > 100*1024 {
		limit = 100 * 1024 // cap at 100KB to prevent memory/context explosion
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, ReadFileOutput{}, fmt.Errorf("failed to load config: %v", err)
	}

	if _, ok := provider.GetNode(input.NodeID); !ok {
		return nil, ReadFileOutput{}, fmt.Errorf("node '%s' not found", input.NodeID)
	}

	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, ReadFileOutput{}, fmt.Errorf("failed to connect to ssh: %v", err)
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, ReadFileOutput{}, fmt.Errorf("failed to create sftp client: %v", err)
	}
	defer sftpClient.Close()

	file, err := sftpClient.SFTPClient().Open(input.Path)
	if err != nil {
		return nil, ReadFileOutput{}, fmt.Errorf("failed to open remote file: %v", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, ReadFileOutput{}, fmt.Errorf("failed to stat file: %v", err)
	}

	if input.Offset > 0 {
		if _, err := file.Seek(input.Offset, io.SeekStart); err != nil {
			return nil, ReadFileOutput{}, fmt.Errorf("failed to seek: %v", err)
		}
	}

	buf := make([]byte, limit)
	n, readErr := file.Read(buf)
	if readErr != nil && readErr != io.EOF {
		return nil, ReadFileOutput{}, fmt.Errorf("failed to read file: %v", readErr)
	}

	isEOF := readErr == io.EOF || int64(n) < limit || (input.Offset+int64(n)) >= stat.Size()

	return nil, ReadFileOutput{
		Content: string(buf[:n]),
		EOF:     isEOF,
		Size:    stat.Size(),
		Status:  "success",
	}, nil
}

type WriteFileInput struct {
	NodeID  string `json:"nodeId" jsonschema:"Node ID for the remote machine"`
	Path    string `json:"path" jsonschema:"Absolute path to the remote file"`
	Content string `json:"content" jsonschema:"Content to write"`
	Append  bool   `json:"append,omitempty" jsonschema:"If true, append to existing file; if false, overwrite completely"`
}

type WriteFileOutput struct {
	BytesWritten int    `json:"bytesWritten" jsonschema:"Number of bytes written"`
	Status       string `json:"status" jsonschema:"Operation status"`
}

func writeFileHandler(ctx context.Context, req *mcp.CallToolRequest, input WriteFileInput) (*mcp.CallToolResult, WriteFileOutput, error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, WriteFileOutput{}, fmt.Errorf("nodeId and path are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, WriteFileOutput{}, fmt.Errorf("failed to load config: %v", err)
	}

	if _, ok := provider.GetNode(input.NodeID); !ok {
		return nil, WriteFileOutput{}, fmt.Errorf("node '%s' not found", input.NodeID)
	}

	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, WriteFileOutput{}, fmt.Errorf("failed to connect to ssh: %v", err)
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, WriteFileOutput{}, fmt.Errorf("failed to create sftp client: %v", err)
	}
	defer sftpClient.Close()

	flags := os.O_WRONLY | os.O_CREATE
	if input.Append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}

	file, err := sftpClient.SFTPClient().OpenFile(input.Path, flags)
	if err != nil {
		return nil, WriteFileOutput{}, fmt.Errorf("failed to open remote file for writing: %v", err)
	}
	defer file.Close()

	n, err := file.Write([]byte(input.Content))
	if err != nil {
		return nil, WriteFileOutput{}, fmt.Errorf("failed to write file: %v", err)
	}

	return nil, WriteFileOutput{
		BytesWritten: n,
		Status:       "success",
	}, nil
}

func uploadFileHandler(ctx context.Context, req *mcp.CallToolRequest, input TransferFileInput) (*mcp.CallToolResult, TransferFileOutput, error) {
	if input.NodeID == "" || input.LocalPath == "" || input.RemotePath == "" {
		return nil, TransferFileOutput{}, fmt.Errorf("nodeId, localPath, and remotePath are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, TransferFileOutput{}, fmt.Errorf("failed to load config: %v", err)
	}

	if _, ok := provider.GetNode(input.NodeID); !ok {
		return nil, TransferFileOutput{}, fmt.Errorf("node '%s' not found", input.NodeID)
	}

	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, TransferFileOutput{}, fmt.Errorf("failed to connect to ssh: %v", err)
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, TransferFileOutput{}, fmt.Errorf("failed to create sftp client: %v", err)
	}
	defer sftpClient.Close()

	if err := sftpClient.Upload(ctx, input.LocalPath, input.RemotePath, nil); err != nil {
		return nil, TransferFileOutput{}, fmt.Errorf("upload failed: %v", err)
	}

	return nil, TransferFileOutput{Status: "success"}, nil
}

func downloadFileHandler(ctx context.Context, req *mcp.CallToolRequest, input TransferFileInput) (*mcp.CallToolResult, TransferFileOutput, error) {
	if input.NodeID == "" || input.LocalPath == "" || input.RemotePath == "" {
		return nil, TransferFileOutput{}, fmt.Errorf("nodeId, localPath, and remotePath are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, TransferFileOutput{}, fmt.Errorf("failed to load config: %v", err)
	}

	if _, ok := provider.GetNode(input.NodeID); !ok {
		return nil, TransferFileOutput{}, fmt.Errorf("node '%s' not found", input.NodeID)
	}

	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, TransferFileOutput{}, fmt.Errorf("failed to connect to ssh: %v", err)
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, TransferFileOutput{}, fmt.Errorf("failed to create sftp client: %v", err)
	}
	defer sftpClient.Close()

	if err := sftpClient.Download(ctx, input.RemotePath, input.LocalPath, nil); err != nil {
		return nil, TransferFileOutput{}, fmt.Errorf("download failed: %v", err)
	}

	return nil, TransferFileOutput{Status: "success"}, nil
}

func RegisterSFTP(server *mcp.Server, g *guardrail.Guardrail) {
	notDestructive := false

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "mtool_read_file",
			Description: "Read a remote file via SFTP. Supports chunked reading via offset and limit to prevent memory overflow on large files. Returns EOF=true if the end of file is reached.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		},
		guardrail.WithGuardrail(g, "mtool_read_file",
			func(in ReadFileInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Path}}
			},
			readFileHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "mtool_write_file",
			Description: "Write or append content to a remote file via SFTP. Use the append flag for chunked writing of large files.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		guardrail.WithGuardrail(g, "mtool_write_file",
			func(in WriteFileInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.Path}}
			},
			writeFileHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "mtool_upload",
			Description: "Upload a local file or directory (from the machine running the MCP server) to the remote node via SFTP. Highly concurrent.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: &notDestructive},
		},
		guardrail.WithGuardrail(g, "mtool_upload",
			func(in TransferFileInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.LocalPath, in.RemotePath}}
			},
			uploadFileHandler,
		),
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "mtool_download",
			Description: "Download a remote file or directory from the node to the machine running the MCP server via SFTP. Highly concurrent.",
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		},
		guardrail.WithGuardrail(g, "mtool_download",
			func(in TransferFileInput) guardrail.RiskInput {
				return guardrail.RiskInput{NodeID: in.NodeID, Paths: []string{in.RemotePath}}
			},
			downloadFileHandler,
		),
	)
}
