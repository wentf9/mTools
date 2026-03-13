package host

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	pkgutils "github.com/wentf9/xops-cli/pkg/utils"
)

var TemplateFile string
var Tag string

func NewCmdInventoryLoad() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "load [csv_file]",
		Short: "从CSV文件加载主机及凭据并验证保存",
		Long: `从CSV文件中加载主机、用户名和密码并保存到配置文件中。
支持表头识别: 主机, 端口, 别名, 用户, 密码, 私钥, 私钥密码
会建立SSH连接验证凭据的准确性。`,
		RunE: RunInventoryLoad,
	}

	cmd.Flags().StringVarP(&TemplateFile, "template", "T", "", "导出CSV导入模板到指定文件")
	cmd.Flags().StringVarP(&Tag, "tag", "t", "", "将导入的主机加入指定标签组")
	return cmd
}

func RunInventoryLoad(cmdObj *cobra.Command, args []string) error {
	// 如果指定了导出模板
	if TemplateFile != "" {
		header := "主机,端口,别名,用户,密码,私钥,私钥密码\n"
		err := os.WriteFile(TemplateFile, []byte(header), 0644)
		if err != nil {
			return fmt.Errorf("导出模板失败: %w", err)
		}
		logger.PrintSuccessf("成功导出模板到: %s", TemplateFile)
		return nil
	}

	if len(args) != 1 {
		return fmt.Errorf("期望一个参数 (CSV文件路径), 但提供了 %d 个 (或使用 -T 导出模板)", len(args))
	}
	csvFile := args[0]
	hosts, err := utils.ReadCSVFile(csvFile)
	if err != nil {
		return fmt.Errorf("读取CSV文件失败: %w", err)
	}

	return ExecuteLoadHost(hosts)
}

func ExecuteLoadHost(hosts []utils.HostInfo) error {
	configPath, keyPath := utils.GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("加载配置文件失败: %w", err)
	}
	provider := config.NewProvider(cfg)
	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	ctx := context.Background()
	wp := pkgutils.NewWorkerPool(uint(len(hosts)))

	for _, host := range hosts {
		h := host // capture
		wp.Execute(func() {
			nodeID, _, err := getOrCreateNode(provider, h)
			if err != nil {
				logger.PrintErrorf("[%s] 配置生成失败: %v", h.Host, err)
				return
			}

			// 验证连接
			client, err := connector.Connect(ctx, nodeID)
			if err != nil {
				logger.PrintErrorf("[%s] 验证失败: %v", h.Host, err)
				return
			}
			_ = client.Close()

			logger.PrintSuccessf("[%s] 验证通过并已保存", h.Host)

		})
	}

	wp.Wait()
	return configStore.Save(cfg)
}

func getOrCreateNode(provider config.ConfigProvider, addr utils.HostInfo) (string, bool, error) {
	host := strings.TrimSpace(addr.Host)
	user := strings.TrimSpace(addr.User)
	port := addr.Port

	if user == "" {
		user = utils.GetCurrentUser()
	}
	if port == 0 {
		port = 22
	}

	nodeID := provider.Find(fmt.Sprintf("%s@%s:%d", user, host, port))
	if nodeID == "" {
		nodeID = provider.Find(host)
	}

	if nodeID != "" {
		updated := updateNodeFromHostInfo(nodeID, provider, addr)
		return nodeID, updated, nil
	}

	// 创建新节点
	nodeID = fmt.Sprintf("%s@%s:%d", user, host, port)

	node := models.Node{
		HostRef:     fmt.Sprintf("%s:%d", host, port),
		IdentityRef: fmt.Sprintf("%s@%s", user, host),
		SudoMode:    models.SudoModeAuto,
	}

	if addr.Alias != "" {
		node.Alias = []string{addr.Alias}
	}

	// 如果指定了全局标签
	if Tag != "" {
		node.Tags = []string{Tag}
	}

	identity := models.Identity{
		User: user,
	}

	if addr.Password != "" {
		identity.Password = addr.Password
		identity.AuthType = "password"
	} else if addr.KeyPath != "" {
		identity.KeyPath = addr.KeyPath
		identity.Passphrase = addr.Passphrase
		identity.AuthType = "key"
	}

	provider.AddHost(node.HostRef, models.Host{Address: host, Port: port})
	provider.AddIdentity(node.IdentityRef, identity)
	provider.AddNode(nodeID, node)

	return nodeID, true, nil
}

func updateNodeFromHostInfo(nodeID string, provider config.ConfigProvider, addr utils.HostInfo) bool {
	node, _ := provider.GetNode(nodeID)
	identity, _ := provider.GetIdentity(nodeID)
	updated := false

	// 更新密码或密钥
	if addr.Password != "" {
		if identity.Password != addr.Password || identity.AuthType != "password" {
			identity.Password = addr.Password
			identity.AuthType = "password"
			updated = true
		}
	} else if addr.KeyPath != "" {
		if identity.KeyPath != addr.KeyPath || identity.Passphrase != addr.Passphrase || identity.AuthType != "key" {
			identity.KeyPath = addr.KeyPath
			identity.Passphrase = addr.Passphrase
			identity.AuthType = "key"
			updated = true
		}
	}

	// 更新别名
	if addr.Alias != "" {
		aliases, changed := appendUnique(node.Alias, addr.Alias)
		if changed {
			node.Alias = aliases
			updated = true
		}
	}

	// 更新标签
	if Tag != "" {
		tags, changed := appendUnique(node.Tags, Tag)
		if changed {
			node.Tags = tags
			updated = true
		}
	}

	if updated {
		provider.AddNode(nodeID, node)
		provider.AddIdentity(node.IdentityRef, identity)
	}

	return updated
}

func appendUnique(slice []string, val string) ([]string, bool) {
	if val == "" {
		return slice, false
	}
	for _, item := range slice {
		if item == val {
			return slice, false
		}
	}
	return append(slice, val), true
}
