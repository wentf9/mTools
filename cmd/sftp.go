package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/config"
	"example.com/MikuTools/pkg/models"
	"example.com/MikuTools/pkg/sftp"
	"example.com/MikuTools/pkg/ssh"
	"github.com/spf13/cobra"
)

type SftpOptions struct {
	SshOptions
	maxTask   int
	maxThread int
}

func NewSftpOptions() *SftpOptions {
	return &SftpOptions{
		SshOptions: *NewSshOptions(),
	}
}

func NewCmdSftp() *cobra.Command {
	o := NewSftpOptions()
	cmd := &cobra.Command{
		Use:   "sftp [user@]host[:port]",
		Short: "通过sftp连接到指定主机",
		Long: `通过sftp连接到指定主机并提供交互式终端。
用法示例:
mtool sftp user@host[:port] [-P password] [--task maxTask] [--thread maxThread]
用户和主机为必选参数,端口默认为22,一般不需要修改
通过flags提供主机和用户信息时会忽略参数提供的信息
如果未通过-p选项显式提供密码,将会从终端输入或通过保存的密码文件读取密码
成功登录过的用户和主机组合的密码将会保存到密码文件中
密码采用对称加密算法加密保存,密码文件位置为~/.mtool_passwords.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Complete(cmd, args)
			if err := o.Validate(); err != nil {
				return fmt.Errorf("参数错误: %v", err)
			}
			return o.Run()
		},
	}
	cmd.Flags().IntVar(&o.maxTask, "task", 0, "同时下载文件数")
	cmd.Flags().IntVar(&o.maxThread, "thread", 0, "单个文件同时下载线程")
	cmd.Flags().StringVarP(&o.Password, "password", "P", "", "SSH密码")
	cmd.Flags().StringVarP(&o.KeyFile, "key", "i", "", "SSH私钥文件路径")
	cmd.Flags().StringVarP(&o.KeyPass, "key_pass", "W", "", "SSH私钥密码")
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "j", "", "跳板机地址[user@]host[:port]")
	cmd.Flags().StringVarP(&o.Alias, "alias", "a", "", "连接别名")
	cmd.MarkFlagsMutuallyExclusive("password", "key")
	return cmd
}

func (o *SftpOptions) Run() error {
	configStore := config.NewDefaultStore(utils.GetConfigFilePath())
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("加载配置文件失败: %v", err)
	}

	provider := config.NewProvider(cfg)

	var nodeId string
	updated := false
	if nodeId = provider.Find(o.Host); nodeId != "" {
		updated = update(nodeId, &o.SshOptions, provider)
	} else if nodeId = provider.Find(fmt.Sprintf("%s@%s:%d", o.User, o.Host, o.Port)); nodeId != "" {
		updated = update(nodeId, &o.SshOptions, provider)
	} else {
		updated = true
		nodeId = fmt.Sprintf("%s@%s:%d", o.User, o.Host, o.Port)
		node := models.Node{
			HostRef:     fmt.Sprintf("%s:%d", o.Host, o.Port),
			IdentityRef: fmt.Sprintf("%s@%s", o.User, o.Host),
			ProxyJump:   o.JumpHost,
			SudoMode:    "sudo",
		}
		if node.ProxyJump != "" {
			jumpHost := provider.Find(node.ProxyJump)
			if jumpHost == "" {
				return fmt.Errorf("跳板机 %s 信息不存在,请先保存跳板机信息", node.ProxyJump)
			}
			node.ProxyJump = jumpHost
		}
		host := models.Host{
			Address: o.Host,
			Port:    o.Port,
		}
		if o.Alias != "" {
			node.Alias = append(node.Alias, o.Alias)
		}
		identity := models.Identity{
			User: o.User,
		}
		if o.Password == "" && o.KeyFile == "" {
			if pass, err := utils.ReadPasswordFromTerminal("请输入密码: "); err != nil {
				return err
			} else {
				identity.Password = pass
				identity.AuthType = "password"
			}
		} else if o.Password != "" {
			identity.Password = o.Password
			identity.AuthType = "password"
		} else if o.KeyFile != "" {
			identity.KeyPath = o.KeyFile
			identity.Passphrase = o.KeyPass
			identity.AuthType = "key"
		}
		provider.AddNode(nodeId, node)
		provider.AddHost(node.HostRef, host)
		provider.AddIdentity(node.IdentityRef, identity)
	}
	connector := ssh.NewConnector(provider)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := connector.Connect(ctx, nodeId)
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer sftpClient.Close()
	defer client.Close()
	// 启动 Shell
	// 使用 os.Stdin, os.Stdout 绑定到当前终端
	shell, err := sftpClient.NewShell(os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		return fmt.Errorf("sftp交互式环境创建失败: %v", err)
	}
	if err := shell.Run(ctx); err != nil {
		return fmt.Errorf("sftp交互式环境启动失败: %v", err)
	}
	if updated {
		if err := configStore.Save(cfg); err != nil {
			return fmt.Errorf("保存配置文件失败: %v", err)
		}
	}
	return nil
}

func init() {
	rootCmd.AddCommand(NewCmdSftp())
}

// func runSFTPWithProgress(localPath, remotePath string, cfg sftp.TransferConfig) {
// 	// ... setup connector ...
// 	var sftpCli sftp.Client
// 	// 1. 计算总大小 (本地上传为例)
// 	var totalSize int64 = 0
// 	filepath.Walk(localPath, func(_ string, info os.FileInfo, _ error) error {
// 		if !info.IsDir() {
// 			totalSize += info.Size()
// 		}
// 		return nil
// 	})

// 	// 2. 初始化进度条
// 	bar := progressbar.DefaultBytes(totalSize, "Uploading")

// 	// 3. 定义回调函数 (原子操作)
// 	callback := func(n int) {
// 		bar.Add(n) // progressbar 库通常是线程安全的，如果是 atomic 可以直接 Add
// 	}

// 	// 4. 开始传输
// 	err := sftpCli.Upload(ctx, localPath, remotePath, cfg, callback)
// 	if err != nil {
// 		// handle error
// 	}
// }
