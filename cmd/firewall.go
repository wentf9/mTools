package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	cmdutils "github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/executor"
	"github.com/wentf9/xops-cli/pkg/firewall"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/ssh"

	"github.com/spf13/cobra"
	pkgutils "github.com/wentf9/xops-cli/pkg/utils"
)

type FirewallOptions struct {
	SshOptions
	HostFile  string
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
		_ = cmd.Help()
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
	firewallCmd.PersistentFlags().StringVarP(&fwOptions.Host, "host", "H", "", "目标主机/连接别名,多个用逗号分隔")
	firewallCmd.PersistentFlags().StringVarP(&fwOptions.HostFile, "ifile", "I", "", "主机列表文件(每行一个主机名或别名)")
	firewallCmd.PersistentFlags().StringVarP(&fwOptions.User, "user", "u", "", "SSH用户名")
	firewallCmd.PersistentFlags().StringVarP(&fwOptions.Password, "password", "w", "", "SSH密码")
	firewallCmd.PersistentFlags().IntVar(&fwOptions.TaskCount, "task", 1, "并行任务数")

	firewallCmd.PersistentFlags().StringVar(&fwOptions.Protocol, "proto", "tcp", "协议类型 (tcp/udp)")
	firewallCmd.PersistentFlags().BoolVarP(&fwOptions.Remove, "remove", "r", false, "是否删除规则")
	firewallCmd.PersistentFlags().BoolVar(&fwOptions.Reload, "reload", false, "操作后是否重载")
	firewallCmd.PersistentFlags().StringVarP(&fwOptions.Zone, "zone", "z", "", "防火墙区域 (仅 firewalld)")
}

func (o *FirewallOptions) RunOnHosts(ctx context.Context, action func(fw firewall.Firewall) (string, error)) error {
	// 如果没有指定主机，默认本地模式
	if o.Host == "" && o.HostFile == "" {
		return o.runLocalFirewall(ctx, action)
	}
	// 远程模式
	return o.runRemoteFirewalls(ctx, action)
}

func (o *FirewallOptions) runLocalFirewall(ctx context.Context, action func(fw firewall.Firewall) (string, error)) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("防火墙管理功能仅支持 Linux 系统 (当前系统为 %s)", runtime.GOOS)
	}
	pwd := cmdutils.GetLocalSudoPassword()
	exec := executor.NewLocalExecutor(pwd)
	fw, err := firewall.DetectFirewall(ctx, exec)
	if err != nil {
		return err
	}
	out, err := action(fw)
	if err != nil {
		logger.PrintErrorf("[LOCAL] (%s) Error: %v\nOutput: %s", fw.Name(), err, out)
	} else {
		logger.PrintSuccessf("[LOCAL] (%s) Success\n%s", fw.Name(), out)
	}
	if o.Reload {
		if _, err := fw.Reload(ctx); err != nil {
			logger.PrintErrorf("[LOCAL] 重启防火墙失败: %v", err)
		}
	}
	return nil
}

func (o *FirewallOptions) runRemoteFirewalls(ctx context.Context, action func(fw firewall.Firewall) (string, error)) error {
	configPath, keyPath := cmdutils.GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return err
	}
	provider := config.NewProvider(cfg)
	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	var hosts []string
	if o.Host != "" {
		hosts = strings.Split(o.Host, ",")
	}
	if o.HostFile != "" {
		data, err := os.ReadFile(o.HostFile)
		if err != nil {
			return fmt.Errorf("读取主机列表文件失败: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				hosts = append(hosts, line)
			}
		}
	}

	wp := pkgutils.NewWorkerPool(uint(o.TaskCount))
	for _, h := range hosts {
		o.executeOnSingleHost(ctx, h, provider, connector, wp, action)
	}

	wp.Wait()
	if err := configStore.Save(cfg); err != nil {
		logger.PrintErrorf("保存配置失败: %v", err)
	}
	return nil
}

func (o *FirewallOptions) executeOnSingleHost(ctx context.Context, h string, provider config.ConfigProvider, connector *ssh.Connector, wp pkgutils.WorkerPool, action func(fw firewall.Firewall) (string, error)) {
	wp.Execute(func() {
		rawHost := strings.TrimSpace(h)
		if rawHost == "" {
			return
		}

		nodeID := provider.Find(rawHost)
		u, hs, p := cmdutils.ParseAddr(rawHost)
		if nodeID == "" {
			if u == "" {
				u = o.User
				if u == "" {
					u = cmdutils.GetCurrentUser()
				}
			}
			if p == 0 {
				p = o.Port
				if p == 0 {
					p = 22
				}
			}
			nodeID = provider.Find(fmt.Sprintf("%s@%s:%d", u, hs, p))
		}

		if nodeID == "" {
			logger.PrintErrorf("[%s@%s:%d] 未找到该主机匹配的节点配置，请先通过 inventory 添加", u, hs, p)
			return
		}

		client, err := connector.Connect(ctx, nodeID)
		if err != nil {
			logger.PrintErrorf("[%s] 连接失败: %v", rawHost, err)
			return
		}

		exec := executor.NewSSHExecutor(client)
		fw, err := firewall.DetectFirewall(ctx, exec)
		if err != nil {
			logger.PrintErrorf("[%s] 探测防火墙失败: %v", rawHost, err)
			return
		}

		out, err := action(fw)
		if err != nil {
			logger.PrintErrorf("[%s] 失败: %v\n输出: %s", rawHost, err, out)
		} else {
			logger.PrintSuccessf("[%s] 成功 (%s)\n%s", rawHost, fw.Name(), out)
		}

		if o.Reload {
			if _, err := fw.Reload(ctx); err != nil {
				logger.PrintErrorf("[%s] 重启防火墙失败: %v", rawHost, err)
			}
		}
	})
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
				var allPorts []string
				for _, arg := range args {
					allPorts = append(allPorts, strings.Split(arg, ",")...)
				}

				for _, p := range allPorts {
					p = strings.TrimSpace(p)
					if p == "" {
						continue
					}
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
		Short: "管理服务规则 (例如: http, https)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fwOptions.RunOnHosts(context.Background(), func(fw firewall.Firewall) (string, error) {
				var finalOut strings.Builder
				var allServices []string
				for _, arg := range args {
					allServices = append(allServices, strings.Split(arg, ",")...)
				}

				for _, s := range allServices {
					s = strings.TrimSpace(s)
					if s == "" {
						continue
					}
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
			var portStr, sourceStr string
			if len(args) == 1 {
				sourceStr = args[0]
			} else {
				portStr = args[0]
				sourceStr = args[1]
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
				var finalOut strings.Builder
				sources := strings.Split(sourceStr, ",")
				var ports []string
				if portStr != "" {
					ports = strings.Split(portStr, ",")
				} else {
					ports = []string{""}
				}

				for _, src := range sources {
					src = strings.TrimSpace(src)
					if src == "" {
						continue
					}
					for _, p := range ports {
						p = strings.TrimSpace(p)
						rule := firewall.Rule{
							Port:     p,
							Source:   src,
							Protocol: firewall.Protocol(fwOptions.Protocol),
							Action:   action,
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
				}
				return finalOut.String(), nil
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
