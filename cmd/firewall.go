package cmd

import (
	"context"
	"fmt"

	"strings"

	cmdutils "example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/config"
	"example.com/MikuTools/pkg/executor"
	"example.com/MikuTools/pkg/firewall"
	"example.com/MikuTools/pkg/ssh"

	pkgutils "example.com/MikuTools/pkg/utils"
	"github.com/spf13/cobra"
)

type FirewallOptions struct {
	SshOptions
	HostFile  string
	CSVFile   string
	Protocol  string
	Reload    bool
	Remove    bool
	Zone      string
	Action    firewall.Action
	TaskCount int
}

func NewFirewallOptions() *FirewallOptions {
	return &FirewallOptions{
		SshOptions: *NewSshOptions(),
		Protocol:   "tcp",
		Action:     firewall.ActionAllow,
		TaskCount:  1,
	}
}

var fwOptions = NewFirewallOptions()

var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "管理目标主机的防火墙设置",
	Long: `支持多后端 (firewalld, ufw, iptables, nftables) 的防火墙管理工具。
会自动探测目标主机使用的防火墙类型。`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(firewallCmd)
	firewallCmd.AddCommand(newFirewallListCmd())
	firewallCmd.AddCommand(newFirewallPortCmd())
	firewallCmd.AddCommand(newFirewallServiceCmd())
	firewallCmd.AddCommand(newFirewallRuleCmd())
	firewallCmd.AddCommand(newFirewallReloadCmd())

	// 通用参数
	firewallCmd.PersistentFlags().StringVarP(&fwOptions.Host, "host", "H", "", "目标主机,多个主机用逗号分隔")
	firewallCmd.PersistentFlags().StringVarP(&fwOptions.User, "user", "u", "", "SSH用户名")
	firewallCmd.PersistentFlags().StringVarP(&fwOptions.Password, "password", "w", "", "SSH密码")
	firewallCmd.PersistentFlags().StringVarP(&fwOptions.HostFile, "ifile", "I", "", "主机列表文件")
	firewallCmd.PersistentFlags().StringVar(&fwOptions.CSVFile, "csv", "", "CSV格式主机列表")
	firewallCmd.PersistentFlags().IntVar(&fwOptions.TaskCount, "task", 1, "并行任务数")

	firewallCmd.PersistentFlags().StringVar(&fwOptions.Protocol, "proto", "tcp", "协议类型 (tcp/udp)")
	firewallCmd.PersistentFlags().BoolVarP(&fwOptions.Remove, "remove", "r", false, "是否删除规则")
	firewallCmd.PersistentFlags().BoolVar(&fwOptions.Reload, "reload", false, "操作后是否重载")
	firewallCmd.PersistentFlags().StringVarP(&fwOptions.Zone, "zone", "z", "", "防火墙区域 (仅 firewalld)")
}

func (o *FirewallOptions) RunOnHosts(ctx context.Context, action func(fw firewall.Firewall) (string, error)) error {
	// 如果没有指定主机，默认本地模式
	if o.Host == "" && o.HostFile == "" && o.CSVFile == "" {
		pwd := cmdutils.GetLocalSudoPassword()
		exec := executor.NewLocalExecutor(pwd)
		fw, err := firewall.DetectFirewall(ctx, exec)
		if err != nil {
			return err
		}
		out, err := action(fw)
		if err != nil {
			fmt.Printf("[LOCAL] Error: %v\nOutput: %s\n", err, out)
		} else {
			fmt.Printf("[LOCAL] Success\n%s\n", out)
		}
		if o.Reload {
			fw.Reload(ctx)
		}
		return nil
	}

	// 远程模式
	configPath, keyPath := cmdutils.GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return err
	}
	provider := config.NewProvider(cfg)
	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	hosts, err := cmdutils.ParseHosts(o.Host, o.HostFile, o.CSVFile)
	if err != nil {
		return err
	}

	wp := pkgutils.NewWorkerPool(uint(o.TaskCount))

	executeOnHost := func(h string) {
		wp.Execute(func() {
			// 这里复用之前 exec.go 中的逻辑或简化
			// 为了简洁，直接使用 Connector

			// 简单的节点查找/创建逻辑 (这里为了重构简洁省略部分逻辑)
			nodeId := provider.Find(h)
			if nodeId == "" {
				// 动态创建一个临时节点或报错
				fmt.Printf("[%s] 未找到节点配置，请先通过 exec 或配置添加\n", h)
				return
			}

			client, err := connector.Connect(ctx, nodeId)
			if err != nil {
				fmt.Printf("[%s] 连接失败: %v\n", h, err)
				return
			}

			exec := executor.NewSSHExecutor(client)
			fw, err := firewall.DetectFirewall(ctx, exec)
			if err != nil {
				fmt.Printf("[%s] 探测防火墙失败: %v\n", h, err)
				return
			}

			out, err := action(fw)
			if err != nil {
				fmt.Printf("[%s] 失败: %v\n输出: %s\n", h, err, out)
			} else {
				fmt.Printf("[%s] 成功 (%s)\n%s\n", h, fw.Name(), out)
			}

			if o.Reload {
				fw.Reload(ctx)
			}
		})
	}

	for _, h := range hosts {
		executeOnHost(fmt.Sprintf("%s@%s:%d", h.User, h.Host, h.Port))
	}

	wp.Wait()
	return nil
}

func newFirewallListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "列出规则",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fwOptions.RunOnHosts(context.Background(), func(fw firewall.Firewall) (string, error) {
				return fw.ListRules(context.Background())
			})
		},
	}
}

func newFirewallPortCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "port <ports>",
		Short: "管理端口规则 (例如: 80, 8080-8090)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fwOptions.RunOnHosts(context.Background(), func(fw firewall.Firewall) (string, error) {
				var finalOut strings.Builder
				for _, p := range args {
					rule := firewall.Rule{
						Port:     p,
						Protocol: firewall.Protocol(fwOptions.Protocol),
						Action:   fwOptions.Action,
					}
					var out string
					var err error
					if fwOptions.Remove {
						out, err = fw.RemoveRule(context.Background(), rule)
					} else {
						out, err = fw.AddRule(context.Background(), rule)
					}
					finalOut.WriteString(out)
					if err != nil {
						return finalOut.String(), err
					}
				}
				return finalOut.String(), nil
			})
		},
	}
}

func newFirewallServiceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "service <services>",
		Short: "管理服务规则 (例如: http, ssh)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fwOptions.RunOnHosts(context.Background(), func(fw firewall.Firewall) (string, error) {
				var finalOut strings.Builder
				for _, s := range args {
					rule := firewall.Rule{
						Service: s,
						Action:  fwOptions.Action,
					}
					var out string
					var err error
					if fwOptions.Remove {
						out, err = fw.RemoveRule(context.Background(), rule)
					} else {
						out, err = fw.AddRule(context.Background(), rule)
					}
					finalOut.WriteString(out)
					if err != nil {
						return finalOut.String(), err
					}
				}
				return finalOut.String(), nil
			})
		},
	}
}

func newFirewallRuleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rule [port] <source_ip>",
		Short: "管理复杂规则 (带源 IP)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var port, source string
			if len(args) == 1 {
				source = args[0]
			} else {
				port = args[0]
				source = args[1]
			}

			reject, _ := cmd.Flags().GetBool("reject")
			drop, _ := cmd.Flags().GetBool("drop")
			action := firewall.ActionAllow
			if reject {
				action = firewall.ActionReject
			} else if drop {
				action = firewall.ActionDrop
			}

			return fwOptions.RunOnHosts(context.Background(), func(fw firewall.Firewall) (string, error) {
				rule := firewall.Rule{
					Port:     port,
					Source:   source,
					Protocol: firewall.Protocol(fwOptions.Protocol),
					Action:   action,
				}
				if fwOptions.Remove {
					return fw.RemoveRule(context.Background(), rule)
				}
				return fw.AddRule(context.Background(), rule)
			})
		},
	}
	cmd.Flags().Bool("reject", false, "使用 REJECT")
	cmd.Flags().Bool("drop", false, "使用 DROP")
	return cmd
}

func newFirewallReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "重载防火墙",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fwOptions.RunOnHosts(context.Background(), func(fw firewall.Firewall) (string, error) {
				return fw.Reload(context.Background())
			})
		},
	}
}
