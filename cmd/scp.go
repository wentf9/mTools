package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cmdutils "example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/config"
	"example.com/MikuTools/pkg/models"
	"example.com/MikuTools/pkg/sftp"
	"example.com/MikuTools/pkg/ssh"
	pkgutils "example.com/MikuTools/pkg/utils"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

type ScpOptions struct {
	SshOptions
	Recursive   bool
	Progress    bool
	Force       bool
	TaskCount   int
	ThreadCount int
	Source      string
	Dest        string
	HostFile    string
	CSVFile     string
}

func NewScpOptions() *ScpOptions {
	return &ScpOptions{
		SshOptions:  *NewSshOptions(),
		TaskCount:   1,
		ThreadCount: sftp.DefaultThreadsPerFile,
	}
}

func NewCmdScp() *cobra.Command {
	o := NewScpOptions()
	cmd := &cobra.Command{
		Use:   "scp [[user@]host:]source [[user@]host:]dest",
		Short: "在本地和远程主机之间传输文件",
		Long: `在本地和远程主机之间传输文件，支持多台主机并行传输。
支持以下场景:
1. 从本地上传到远程: mtool scp local_path user@host:remote_path
2. 从远程下载到本地: mtool scp user@host:remote_path local_path
3. 远程到远程传输: mtool scp user1@host1:path1 user2@host2:path2
4. 批量上传到多台主机: mtool scp local_path --dest remote_path -H host1,host2

通过flags提供主机和用户信息时会覆盖参数提供的信息。
如果未通过-w选项显式提供密码, 将会从终端输入或通过保存的配置文件读取。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Complete(cmd, args)
			if err := o.Validate(); err != nil {
				return err
			}
			return o.Run()
		},
	}

	// 基础连接参数
	cmd.Flags().StringVarP(&o.Host, "host", "H", "", "目标主机,多个主机用逗号分隔")
	cmd.Flags().Uint16VarP(&o.Port, "port", "P", 0, "SSH端口")
	cmd.Flags().StringVarP(&o.User, "user", "u", "", "SSH用户名")
	cmd.Flags().StringVarP(&o.Password, "password", "w", "", "SSH密码")
	cmd.Flags().StringVarP(&o.KeyFile, "key", "i", "", "SSH私钥文件路径")
	cmd.Flags().StringVarP(&o.KeyPass, "key_pass", "W", "", "SSH私钥密码")
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "j", "", "跳板机地址[user@]host[:port]")
	cmd.Flags().StringVarP(&o.Alias, "alias", "a", "", "连接别名")

	// SCP 特有参数
	cmd.Flags().StringVar(&o.Source, "src", "", "源路径 (批量模式使用)")
	cmd.Flags().StringVar(&o.Dest, "dest", "", "目标路径 (批量模式使用)")
	cmd.Flags().StringVarP(&o.HostFile, "ifile", "I", "", "主机列表文件路径")
	cmd.Flags().StringVar(&o.CSVFile, "csv", "", "CSV文件路径 (ip,user,password)")
	cmd.Flags().BoolVarP(&o.Recursive, "recursive", "r", false, "递归复制目录")
	cmd.Flags().BoolVarP(&o.Progress, "progress", "v", false, "显示传输进度")
	cmd.Flags().BoolVarP(&o.Force, "force", "f", false, "强制覆盖远程文件")
	cmd.Flags().IntVar(&o.TaskCount, "task", 1, "并行传输的主机数")
	cmd.Flags().IntVar(&o.ThreadCount, "thread", 4, "单个文件传输的并发线程数")

	cmd.MarkFlagsMutuallyExclusive("password", "key")
	cmd.MarkFlagsMutuallyExclusive("host", "ifile", "csv")
	return cmd
}

func (o *ScpOptions) Complete(cmd *cobra.Command, args []string) {
	o.args = args
	if len(args) == 2 {
		if o.Source == "" {
			o.Source = args[0]
		}
		if o.Dest == "" {
			o.Dest = args[1]
		}
	} else if len(args) == 1 {
		if o.Source == "" {
			o.Source = args[0]
		}
	}
}

func (o *ScpOptions) Validate() error {
	if o.Source == "" {
		return fmt.Errorf("必须指定源路径")
	}
	if o.Dest == "" && o.Host == "" {
		return fmt.Errorf("必须指定目标路径或目标主机")
	}
	return nil
}

type PathInfo struct {
	IsRemote bool
	User     string
	Host     string
	Port     uint16
	Path     string
}

func parsePath(p string) PathInfo {
	if strings.Contains(p, ":") {
		// 检查是否是 Windows 盘符
		if len(p) >= 2 && p[1] == ':' && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) {
			// 如果冒号后面没有其他冒号，认为是本地路径
			if !strings.Contains(p[2:], ":") {
				return PathInfo{IsRemote: false, Path: p}
			}
		}

		parts := strings.SplitN(p, ":", 2)
		addr := parts[0]
		path := parts[1]
		u, h, port := cmdutils.ParseAddr(addr)
		return PathInfo{
			IsRemote: true,
			User:     u,
			Host:     h,
			Port:     port,
			Path:     path,
		}
	}
	return PathInfo{IsRemote: false, Path: p}
}

func (o *ScpOptions) Run() error {
	configPath, keyPath := cmdutils.GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("加载配置文件失败: %v", err)
	}
	provider := config.NewProvider(cfg)
	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	src := parsePath(o.Source)
	var dst PathInfo
	if o.Dest != "" {
		dst = parsePath(o.Dest)
	}

	ctx := context.Background()

	// 1. 批量上传模式 (-H host1,host2 或 -I hostfile 或 --csv file)
	if (o.Host != "" && strings.Contains(o.Host, ",")) || o.HostFile != "" || o.CSVFile != "" {
		return o.runBatch(ctx, provider, connector, configStore, cfg)
	}

	// 2. 远程到远程
	if src.IsRemote && dst.IsRemote {
		return o.runRemoteToRemote(ctx, src, dst, provider, connector, configStore, cfg)
	}

	// 3. 单主机上传/下载
	if src.IsRemote {
		return o.runDownload(ctx, src, o.Dest, provider, connector, configStore, cfg)
	} else if dst.IsRemote {
		return o.runUpload(ctx, o.Source, dst, provider, connector, configStore, cfg)
	}

	return fmt.Errorf("不支持的传输模式: 两端都是本地路径")
}

func (o *ScpOptions) runUpload(ctx context.Context, localPath string, dst PathInfo, provider config.ConfigProvider, connector *ssh.Connector, configStore config.Store, cfg *config.Configuration) error {
	nodeId, updated, err := o.getOrCreateNodeForPath(provider, dst, "")
	if err != nil {
		return err
	}
	if updated {
		configStore.Save(cfg)
	}

	client, err := connector.Connect(ctx, nodeId)
	if err != nil {
		return err
	}

	sftpCli, err := sftp.NewClient(client, sftp.WithThreadsPerFile(o.ThreadCount))
	if err != nil {
		return err
	}
	defer sftpCli.Close()

	var progress sftp.ProgressCallback
	if o.Progress {
		info, err := os.Stat(localPath)
		if err != nil {
			return err
		}
		description := "Uploading " + filepath.Base(localPath)
		bar := progressbar.NewOptions64(
			info.Size(),
			progressbar.OptionSetDescription(description),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(30),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionShowCount(),
			progressbar.OptionOnCompletion(func() {
				fmt.Fprint(os.Stderr, "\n")
			}),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
		)
		progress = func(n int) { bar.Add(n) }
	}

	return sftpCli.Upload(ctx, localPath, dst.Path, progress)
}

func (o *ScpOptions) runDownload(ctx context.Context, src PathInfo, localPath string, provider config.ConfigProvider, connector *ssh.Connector, configStore config.Store, cfg *config.Configuration) error {
	nodeId, updated, err := o.getOrCreateNodeForPath(provider, src, "")
	if err != nil {
		return err
	}
	if updated {
		configStore.Save(cfg)
	}

	client, err := connector.Connect(ctx, nodeId)
	if err != nil {
		return err
	}

	sftpCli, err := sftp.NewClient(client, sftp.WithThreadsPerFile(o.ThreadCount))
	if err != nil {
		return err
	}
	defer sftpCli.Close()

	// 只 Stat 一次
	stat, err := sftpCli.SFTPClient().Stat(src.Path)
	if err != nil {
		return fmt.Errorf("stat remote path failed: %w", err)
	}

	var progress sftp.ProgressCallback
	if o.Progress {
		description := "Downloading " + filepath.Base(src.Path)
		bar := progressbar.NewOptions64(
			stat.Size(),
			progressbar.OptionSetDescription(description),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(30),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionShowCount(),
			progressbar.OptionOnCompletion(func() {
				fmt.Fprint(os.Stderr, "\n")
			}),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
		)
		progress = func(n int) { bar.Add(n) }
	}

	if stat.IsDir() {
		return sftpCli.DownloadDirectory(ctx, src.Path, localPath, progress)
	}

	// 处理本地路径是目录的情况
	localDest := localPath
	if lStat, err := os.Stat(localPath); err == nil && lStat.IsDir() {
		localDest = filepath.Join(localPath, stat.Name())
	}

	return sftpCli.DownloadFile(ctx, src.Path, localDest, stat.Size(), stat.Mode(), progress)
}

func (o *ScpOptions) runRemoteToRemote(ctx context.Context, src, dst PathInfo, provider config.ConfigProvider, connector *ssh.Connector, configStore config.Store, cfg *config.Configuration) error {
	srcNodeId, srcUpdated, err := o.getOrCreateNodeForPath(provider, src, "")
	if err != nil {
		return err
	}
	dstNodeId, dstUpdated, err := o.getOrCreateNodeForPath(provider, dst, "")
	if err != nil {
		return err
	}

	if srcUpdated || dstUpdated {
		configStore.Save(cfg)
	}

	srcClient, err := connector.Connect(ctx, srcNodeId)
	if err != nil {
		return err
	}
	dstClient, err := connector.Connect(ctx, dstNodeId)
	if err != nil {
		return err
	}

	srcSftp, err := sftp.NewClient(srcClient)
	if err != nil {
		return err
	}
	defer srcSftp.Close()

	dstSftp, err := sftp.NewClient(dstClient)
	if err != nil {
		return err
	}
	defer dstSftp.Close()

	srcFile, err := srcSftp.SFTPClient().Open(src.Path)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	stat, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstPath := dst.Path
	dstStat, err := dstSftp.SFTPClient().Stat(dstPath)
	if err == nil && dstStat.IsDir() {
		dstPath = dstSftp.JoinPath(dstPath, filepath.Base(src.Path))
	}

	dstFile, err := dstSftp.SFTPClient().Create(dstPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	var progress sftp.ProgressCallback
	if o.Progress {
		bar := progressbar.DefaultBytes(stat.Size(), "Relaying "+filepath.Base(src.Path))
		progress = func(n int) { bar.Add(n) }
	}

	return dstSftp.StreamTransfer(srcFile, dstFile, progress)
}

func (o *ScpOptions) runBatch(ctx context.Context, provider config.ConfigProvider, connector *ssh.Connector, configStore config.Store, cfg *config.Configuration) error {
	hosts, csvHosts, err := cmdutils.ParseHosts(o.Host, o.HostFile, o.CSVFile)
	if err != nil {
		return err
	}

	wp := pkgutils.NewWorkerPool(uint(o.TaskCount))

	// 处理 普通主机列表
	for _, h := range hosts {
		h := h
		wp.Execute(func() {
			addr := PathInfo{Host: h, User: o.User, Port: o.Port, IsRemote: true}
			o.executeTransfer(ctx, h, addr, o.Password, provider, connector, configStore, cfg)
		})
	}

	// 处理 CSV 主机列表
	for _, ch := range csvHosts {
		ch := ch
		wp.Execute(func() {
			// CSV 中的信息优先级高
			addr := PathInfo{Host: ch.IP, User: ch.User, IsRemote: true}
			o.executeTransfer(ctx, ch.IP, addr, ch.Password, provider, connector, configStore, cfg)
		})
	}

	wp.Wait()
	return nil
}

func (o *ScpOptions) executeTransfer(ctx context.Context, label string, addr PathInfo, specificPassword string, provider config.ConfigProvider, connector *ssh.Connector, configStore config.Store, cfg *config.Configuration) {
	nodeId, updated, err := o.getOrCreateNodeForPath(provider, addr, specificPassword)
	if err != nil {
		fmt.Printf("[%s] 错误: %v\n", label, err)
		return
	}
	if updated {
		configStore.Save(cfg)
	}

	client, err := connector.Connect(ctx, nodeId)
	if err != nil {
		fmt.Printf("[%s] 连接失败: %v\n", label, err)
		return
	}

	sftpCli, err := sftp.NewClient(client, sftp.WithThreadsPerFile(o.ThreadCount))
	if err != nil {
		fmt.Printf("[%s] SFTP失败: %v\n", label, err)
		return
	}
	defer sftpCli.Close()

	err = sftpCli.Upload(ctx, o.Source, o.Dest, nil)
	if err != nil {
		fmt.Printf("[%s] 传输失败: %v\n", label, err)
	} else {
		fmt.Printf("[%s] 完成\n", label)
	}
}

func (o *ScpOptions) getOrCreateNodeForPath(provider config.ConfigProvider, path PathInfo, specificPassword string) (string, bool, error) {
	host := path.Host
	user := path.User
	port := path.Port

	// 如果没有在路径中指定，使用命令行 flags 中的值
	if host == "" && o.Host != "" && !strings.Contains(o.Host, ",") {
		host = o.Host
	}
	if user == "" && o.User != "" {
		user = o.User
	}
	if port == 0 && o.Port != 0 {
		port = o.Port
	}

	if host == "" {
		return "", false, fmt.Errorf("主机地址不能为空")
	}
	if user == "" {
		user = cmdutils.GetCurrentUser()
	}
	if port == 0 {
		port = 22
	}

	nodeId := provider.Find(host)
	if nodeId == "" {
		nodeId = provider.Find(fmt.Sprintf("%s@%s:%d", user, host, port))
	}

	if nodeId != "" {
		updated := o.updateNode(nodeId, provider, specificPassword)
		return nodeId, updated, nil
	}

	// 创建新节点
	nodeId = fmt.Sprintf("%s@%s:%d", user, host, port)
	node := models.Node{
		HostRef:     fmt.Sprintf("%s:%d", host, port),
		IdentityRef: fmt.Sprintf("%s@%s", user, host),
		ProxyJump:   o.JumpHost,
		SudoMode:    "sudo",
	}

	if node.ProxyJump != "" {
		jumpHost := provider.Find(node.ProxyJump)
		if jumpHost == "" {
			return "", false, fmt.Errorf("跳板机 %s 信息不存在", node.ProxyJump)
		}
		node.ProxyJump = jumpHost
	}

	if o.Alias != "" {
		node.Alias = append(node.Alias, o.Alias)
	}

	identity := models.Identity{
		User: user,
	}

	password := specificPassword
	if password == "" && o.Password != "" {
		password = o.Password
	}

	if password == "" && o.KeyFile == "" {
		pass, err := cmdutils.ReadPasswordFromTerminal(fmt.Sprintf("请输入 %s@%s 的密码: ", user, host))
		if err != nil {
			return "", false, err
		}
		password = pass
	}

	if password != "" {
		identity.Password = password
		identity.AuthType = "password"
	} else if o.KeyFile != "" {
		identity.KeyPath = o.KeyFile
		identity.Passphrase = o.KeyPass
		identity.AuthType = "key"
	}

	provider.AddNode(nodeId, node)
	provider.AddHost(node.HostRef, models.Host{Address: host, Port: port})
	provider.AddIdentity(node.IdentityRef, identity)

	return nodeId, true, nil
}

func (o *ScpOptions) updateNode(nodeId string, provider config.ConfigProvider, specificPassword string) bool {
	node, _ := provider.GetNode(nodeId)
	identity, _ := provider.GetIdentity(nodeId)
	updated := false

	password := specificPassword
	if password == "" && o.Password != "" {
		password = o.Password
	}

	if password != "" {
		identity.Password = password
		identity.AuthType = "password"
		updated = true
	} else if o.KeyFile != "" {
		identity.KeyPath = o.KeyFile
		identity.AuthType = "key"
		updated = true
	}

	if o.KeyPass != "" {
		identity.Passphrase = o.KeyPass
		updated = true
	}

	if updated {
		provider.AddIdentity(node.IdentityRef, identity)
	}

	return updated
}

func init() {
	rootCmd.AddCommand(NewCmdScp())
}
