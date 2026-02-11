package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/config"
	"example.com/MikuTools/pkg/models"
	"github.com/spf13/cobra"
)

func NewCmdInventory() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "inventory",
		Aliases: []string{"host", "hosts", "inv"},
		Short:   "管理存储的主机和节点信息",
		Long:    `管理存储的主机、身份认证和节点信息。支持列出、添加和删除操作。`,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	cmd.AddCommand(NewCmdInventoryList())
	cmd.AddCommand(NewCmdInventoryAdd())
	cmd.AddCommand(NewCmdInventoryDelete())
	cmd.AddCommand(NewCmdInventoryTags())

	return cmd
}

func NewCmdInventoryList() *cobra.Command {
	var tagFilter string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "列出所有存储的节点",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, keyPath := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				fmt.Printf("加载配置文件失败: %v\n", err)
				return
			}

			provider := config.NewProvider(cfg)
			var nodes map[string]models.Node
			if tagFilter != "" {
				nodes = provider.GetNodesByTag(tagFilter)
			} else {
				nodes = provider.ListNodes()
			}

			if len(nodes) == 0 {
				if tagFilter != "" {
					fmt.Printf("没有找到带有标签 %s 的节点。\n", tagFilter)
				} else {
					fmt.Println("没有找到已存储的节点。")
				}
				return
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "名称/ID\t别名\t主机地址\t用户\t认证方式\t跳板机\t标签")

			// 排序以便稳定显示
			keys := make([]string, 0, len(nodes))
			for k := range nodes {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, nodeId := range keys {
				node := nodes[nodeId]
				host, _ := provider.GetHost(nodeId)
				identity, _ := provider.GetIdentity(nodeId)

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					nodeId,
					strings.Join(node.Alias, ", "),
					fmt.Sprintf("%s:%d", host.Address, host.Port),
					identity.User,
					identity.AuthType,
					node.ProxyJump,
					strings.Join(node.Tags, ", "),
				)
			}
			w.Flush()
		},
	}
	cmd.Flags().StringVarP(&tagFilter, "tag", "t", "", "按标签筛选节点")
	return cmd
}

func NewCmdInventoryTags() *cobra.Command {
	return &cobra.Command{
		Use:   "tags",
		Short: "列出所有标签及对应的节点数量",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, keyPath := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				fmt.Printf("加载配置文件失败: %v\n", err)
				return
			}

			provider := config.NewProvider(cfg)
			nodes := provider.ListNodes()

			tagMap := make(map[string]int)
			for _, node := range nodes {
				for _, tag := range node.Tags {
					tagMap[tag]++
				}
			}

			if len(tagMap) == 0 {
				fmt.Println("当前没有已定义的标签。")
				return
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "标签\t节点数量")

			tags := make([]string, 0, len(tagMap))
			for t := range tagMap {
				tags = append(tags, t)
			}
			sort.Strings(tags)

			for _, t := range tags {
				fmt.Fprintf(w, "%s\t%d\n", t, tagMap[t])
			}
			w.Flush()
		},
	}
}

func NewCmdInventoryAdd() *cobra.Command {
	var (
		name     string
		address  string
		port     uint16
		user     string
		password string
		keyPath  string
		alias    []string
		tags     []string
		jump     string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "添加一个新节点",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("必须指定节点名称 (--name)")
			}
			if address == "" {
				return fmt.Errorf("必须指定主机地址 (--address)")
			}

			configPath, keyPathCfg := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPathCfg)
			cfg, err := configStore.Load()
			if err != nil {
				return fmt.Errorf("加载配置文件失败: %v", err)
			}

			provider := config.NewProvider(cfg)
			if _, ok := provider.GetNode(name); ok {
				return fmt.Errorf("节点 %s 已存在", name)
			}

			if user == "" {
				user = utils.GetCurrentUser()
			}
			if port == 0 {
				port = 22
			}

			hostObj := models.Host{
				Address: address,
				Port:    port,
			}

			identity := models.Identity{
				User: user,
			}

			if keyPath != "" {
				identity.KeyPath = keyPath
				identity.AuthType = "key"
			} else if password != "" {
				identity.Password = password
				identity.AuthType = "password"
			} else {
				// 交互式读取密码
				pass, err := utils.ReadPasswordFromTerminal(fmt.Sprintf("请输入用户 %s 的密码: ", user))
				if err != nil {
					return err
				}
				identity.Password = pass
				identity.AuthType = "password"
			}

			node := models.Node{
				HostRef:     fmt.Sprintf("host-%s", name),
				IdentityRef: fmt.Sprintf("id-%s", name),
				Alias:       alias,
				Tags:        tags,
				ProxyJump:   jump,
				SudoMode:    "sudo",
			}

			provider.AddHost(node.HostRef, hostObj)
			provider.AddIdentity(node.IdentityRef, identity)
			provider.AddNode(name, node)

			if err := configStore.Save(cfg); err != nil {
				return fmt.Errorf("保存配置文件失败: %v", err)
			}

			fmt.Printf("成功添加节点: %s\n", name)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "节点唯一名称")
	cmd.Flags().StringVar(&address, "address", "", "主机 IP 或域名")
	cmd.Flags().Uint16Var(&port, "port", 22, "SSH 端口")
	cmd.Flags().StringVar(&user, "user", "", "SSH 用户名 (默认为当前用户)")
	cmd.Flags().StringVar(&password, "password", "", "SSH 密码")
	cmd.Flags().StringVar(&keyPath, "key", "", "SSH 私钥路径")
	cmd.Flags().StringSliceVar(&alias, "alias", []string{}, "节点别名 (逗号分隔)")
	cmd.Flags().StringSliceVar(&tags, "tags", []string{}, "节点标签 (逗号分隔)")
	cmd.Flags().StringVar(&jump, "jump", "", "跳板机名称")

	return cmd
}

func NewCmdInventoryDelete() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [name]",
		Short: "删除一个存储的节点",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			configPath, keyPath := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				return fmt.Errorf("加载配置文件失败: %v", err)
			}

			provider := config.NewProvider(cfg)
			if _, ok := provider.GetNode(name); !ok {
				return fmt.Errorf("节点 %s 不存在", name)
			}

			provider.DeleteNode(name)

			if err := configStore.Save(cfg); err != nil {
				return fmt.Errorf("保存配置文件失败: %v", err)
			}

			fmt.Printf("成功删除节点: %s\n", name)
			return nil
		},
	}
}

func init() {
	rootCmd.AddCommand(NewCmdInventory())
}
