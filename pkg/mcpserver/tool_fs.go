package mcpserver

import (
	"context"
	"fmt"
	"time"

	"example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/sftp"
	"example.com/MikuTools/pkg/ssh"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ======================== LS ========================

type FSListInput struct {
	NodeID string `json:"nodeId" jsonschema:"Node ID for the remote machine"`
	Path   string `json:"path" jsonschema:"Absolute path to the remote directory"`
}

type FileInfo struct {
	Name    string    `json:"name" jsonschema:"File name"`
	Size    int64     `json:"size" jsonschema:"Size in bytes"`
	Mode    string    `json:"mode" jsonschema:"File mode/permissions"`
	ModTime time.Time `json:"modTime" jsonschema:"Last modification time"`
	IsDir   bool      `json:"isDir" jsonschema:"True if it is a directory"`
}

type FSListOutput struct {
	Files  []FileInfo `json:"files" jsonschema:"List of files in the directory"`
	Status string     `json:"status" jsonschema:"Operation status"`
}

func fsLsHandler(ctx context.Context, req *mcp.CallToolRequest, input FSListInput) (*mcp.CallToolResult, FSListOutput, error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, FSListOutput{}, fmt.Errorf("nodeId and path are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, FSListOutput{}, fmt.Errorf("failed to load config: %v", err)
	}

	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, FSListOutput{}, fmt.Errorf("failed to connect to ssh: %v", err)
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, FSListOutput{}, fmt.Errorf("failed to create sftp client: %v", err)
	}
	defer sftpClient.Close()

	infos, err := sftpClient.SFTPClient().ReadDir(input.Path)
	if err != nil {
		return nil, FSListOutput{}, fmt.Errorf("ls failed: %v", err)
	}

	var files []FileInfo
	for _, info := range infos {
		files = append(files, FileInfo{
			Name:    info.Name(),
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime(),
			IsDir:   info.IsDir(),
		})
	}

	return nil, FSListOutput{
		Files:  files,
		Status: "success",
	}, nil
}

// ======================== MKDIR ========================

type FSMkdirInput struct {
	NodeID string `json:"nodeId" jsonschema:"Node ID for the remote machine"`
	Path   string `json:"path" jsonschema:"Absolute path to the directory to create"`
}

type FSBaseOutput struct {
	Status string `json:"status" jsonschema:"Operation status"`
}

func fsMkdirHandler(ctx context.Context, req *mcp.CallToolRequest, input FSMkdirInput) (*mcp.CallToolResult, FSBaseOutput, error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeId and path are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}
	defer sftpClient.Close()

	if err := sftpClient.SFTPClient().MkdirAll(input.Path); err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("mkdir failed: %v", err)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== TOUCH ========================

type FSTouchInput struct {
	NodeID string `json:"nodeId" jsonschema:"Node ID for the remote machine"`
	Path   string `json:"path" jsonschema:"Absolute path to the file to create"`
}

func fsTouchHandler(ctx context.Context, req *mcp.CallToolRequest, input FSTouchInput) (*mcp.CallToolResult, FSBaseOutput, error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeId and path are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}
	defer sftpClient.Close()

	file, err := sftpClient.SFTPClient().Create(input.Path)
	if err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("touch failed: %v", err)
	}
	file.Close()

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== MV / RENAME ========================

type FSMvInput struct {
	NodeID string `json:"nodeId" jsonschema:"Node ID for the remote machine"`
	Old    string `json:"oldPath" jsonschema:"Original absolute path"`
	New    string `json:"newPath" jsonschema:"New absolute destination path"`
}

func fsMvHandler(ctx context.Context, req *mcp.CallToolRequest, input FSMvInput) (*mcp.CallToolResult, FSBaseOutput, error) {
	if input.NodeID == "" || input.Old == "" || input.New == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeId, oldPath and newPath are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}
	defer sftpClient.Close()

	if err := sftpClient.SFTPClient().Rename(input.Old, input.New); err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("mv failed: %v", err)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== RM (Bypass via SSH run) ========================

type FSRmInput struct {
	NodeID string `json:"nodeId" jsonschema:"Node ID for the remote machine"`
	Path   string `json:"path" jsonschema:"Absolute path to the file/directory to securely delete"`
}

func fsRmHandler(ctx context.Context, req *mcp.CallToolRequest, input FSRmInput) (*mcp.CallToolResult, FSBaseOutput, error) {
	if input.NodeID == "" || input.Path == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeId and path are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	cmd := fmt.Sprintf("rm -rf '%s'", input.Path)
	output, err := sshClient.Run(ctx, cmd)
	if err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("rm failed: %v, output: %s", err, output)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== CP (Bypass via SSH run) ========================

type FSCpInput struct {
	NodeID string `json:"nodeId" jsonschema:"Node ID for the remote machine"`
	Src    string `json:"srcPath" jsonschema:"Absolute path to source"`
	Dest   string `json:"destPath" jsonschema:"Absolute path to destination"`
}

func fsCpHandler(ctx context.Context, req *mcp.CallToolRequest, input FSCpInput) (*mcp.CallToolResult, FSBaseOutput, error) {
	if input.NodeID == "" || input.Src == "" || input.Dest == "" {
		return nil, FSBaseOutput{}, fmt.Errorf("nodeId, srcPath and destPath are required")
	}

	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	sshClient, err := connector.Connect(ctx, input.NodeID)
	if err != nil {
		return nil, FSBaseOutput{}, err
	}

	cmd := fmt.Sprintf("cp -r '%s' '%s'", input.Src, input.Dest)
	output, err := sshClient.Run(ctx, cmd)
	if err != nil {
		return nil, FSBaseOutput{}, fmt.Errorf("cp failed: %v, output: %s", err, output)
	}

	return nil, FSBaseOutput{Status: "success"}, nil
}

// ======================== REGISTER ========================

func RegisterFS(server *mcp.Server) {
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "mtool_fs_ls",
			Description: "List remote directory files with attributes (size, modTime, isDir, permissions).",
		},
		fsLsHandler,
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "mtool_fs_mkdir",
			Description: "Create a remote directory, along with any necessary parents.",
		},
		fsMkdirHandler,
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "mtool_fs_touch",
			Description: "Create a new empty remote file.",
		},
		fsTouchHandler,
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "mtool_fs_mv",
			Description: "Move or rename a remote file/directory.",
		},
		fsMvHandler,
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "mtool_fs_rm",
			Description: "Remove a remote file or directory recursively safely.",
		},
		fsRmHandler,
	)

	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "mtool_fs_cp",
			Description: "Copy a remote file or directory to another remote location recursively.",
		},
		fsCpHandler,
	)
}
