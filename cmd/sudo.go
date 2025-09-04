package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"example.com/MikuTools/utils"
	"github.com/spf13/cobra"
)

// dnsCmd represents the loadPwd command
var sudoCmd = &cobra.Command{
	Use:   "sudo [command] [-p password]",
	Short: "在本机sudo执行命令",
	Long: `在本机sudo执行命令
	示例:
	mtool sudo 'ss -tlpn'
	mtool sudo 'firewall-cmd --list-all' -p password`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		rootCmd.PersistentPreRun(rootCmd, args)
		if !utils.IsLinux() {
			fmt.Fprintf(os.Stderr, "错误: 仅支持在Linux系统上使用此命令\n")
			os.Exit(1)
		}
	},
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		// 加载密码存储
		passwords, err := utils.LoadPasswords()
		if err != nil {
			fmt.Fprintf(os.Stderr, "无法加载密码存储: %v\n", err)
			passwords = utils.NewPasswordStore()
		}
		passwordModified := false

		if password == "" {
			if storedPass, ok := passwords.GetPass(utils.GetCurrentUser(), utils.GetLocalIp()); ok {
				password = storedPass
			} else {
				if newPass, err := utils.ReadPasswordFromTerminal(fmt.Sprintf("请输入 %s 的密码: ", utils.GetCurrentUser())); err == nil {
					password = newPass
				} else {
					fmt.Fprintf(os.Stderr, "读取密码失败: %v\n", err)
					return
				}
			}
		}
		if len(args) == 0 { // todo
			utils.Logger.Debug("执行sudo命令")
			c := exec.Command("sudo", "-s")
			stdin, err := c.StdinPipe()
			if err != nil {
				fmt.Fprintf(os.Stdout, "创建stdin管道失败: %v", err)
				return
			}
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			if err := c.Start(); err != nil {
				fmt.Println("Error starting command:", err)
				return
			}
			// 等待一段时间让sudo提示出现
			time.Sleep(100 * time.Millisecond)

			if _, err := stdin.Write([]byte(password + "\n")); err != nil {
				fmt.Println("Error writing password:", err)
				return
			}
			stdin.Close()
			if err := c.Wait(); err != nil {
				fmt.Println("Command execution error:", err)
			}
		} else {
			sudoC := exec.Command("bash", "-c", fmt.Sprintf("echo '%s' | sudo -S %s", password, strings.Join(args, " ")))

			output, err := sudoC.CombinedOutput()
			if err != nil {
				fmt.Printf("命令执行错误: %v\n%s", err, output)
				return
			}
			fmt.Printf("执行结果: %s", output)

		}
		if password != "" {
			passwordModified = passwords.SaveOrUpdate(utils.GetCurrentUser(), utils.GetLocalIp(), password)
		}
		if passwordModified {
			if err := passwords.Save2File(); err != nil {
				fmt.Fprintf(os.Stderr, "保存密码到文件失败: %v", err)
			} else {
				utils.Logger.Info(fmt.Sprintf("密码已保存到文件: %s@%s", user, ip))
			}
		}

	},
}

func init() {
	rootCmd.AddCommand(sudoCmd)
	sudoCmd.Flags().StringVarP(&password, "passwd", "p", "", "SSH密码")
}
