/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"regexp"

	"example.com/MikuTools/utils"
	"github.com/spf13/cobra"

	// "os/exec"
	"bufio"
	// "container/list"
	"io"
	"strings"
	"sync"
)

type hostInfo struct {
	ip       string
	user     string
	password string
}

var (
	ip        string
	port      uint16
	user      string
	password  string
	command   string
	hostFile  string
	cmdFile   string
	shellFile string
	csvFile   string
	sudo      uint8
	suPwd     string
	// keyFile string
)

// execCmd represents the exec command
var execCmd = &cobra.Command{
	Use:   "exec [-u user] -i ip -c command [-p password] [-S]",
	Short: "对多台主机执行命令",
	Long: `一条命令在多台主机执行
	用法：
	mtool exec -u user -i ip -c command
	如果未通过-p选项显式提供密码,将会从终端输入或通过保存的密码文件读取密码
	成功登录过的用户和ip组合的密码将会保存到密码文件中
	密码采用对称加密算法加密保存,密码文件位置为~/.mtool_passwords.json`,
	Run: func(cmd *cobra.Command, args []string) {
		isShell := false
		issu, _ := cmd.Flags().GetBool("su")
		issudo, _ := cmd.Flags().GetBool("sudo")
		if issu || issudo {
			if issu {
				sudo = 2
			} else {
				sudo = 1
			}
		} else {
			sudo = 0
		}
		if shellFile != "" {
			if file, err := os.Open(shellFile); err == nil {
				// 读取shell脚本内容
				shellContent, err := io.ReadAll(file)
				if err != nil {
					fmt.Fprintf(os.Stderr, "读取shell脚本失败: %v\n", err)
					os.Exit(1)
				}
				command = string(shellContent)
				file.Close()
			} else {
				fmt.Fprintf(os.Stderr, "打开shell脚本失败: %v\n", err)
				os.Exit(1)
			}
			isShell = true
		}
		sshCommand := utils.NewSSHCommand(command, sudo, isShell)
		hosts, csvHosts, err := parseHosts(ip, hostFile, csvFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "解析主机列表失败: %v\n", err)
			os.Exit(1)
		}
		concurrency := len(hosts)
		if csvFile != "" {
			concurrency = len(csvHosts)
		}
		ExecuteConcurrently(hosts, csvHosts, sshCommand, concurrency)
	},
}

func bufferedReadIpFile(path string) []string {
	var hosts []string
	file, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	// 预览前5字节（不移动读取指针）
	// peekBytes, err := reader.Peek(5)
	// fmt.Println("预览内容：", string(peekBytes))
	reg := regexp.MustCompile(`\s`)
	// 逐行读取
	for {
		line, err := reader.ReadString('\n') // 读取到换行符
		if err == nil {
			line = reg.ReplaceAllString(line, "")
			if line == "" {
				continue
			}
			hosts = append(hosts, line)
		} else if err == io.EOF {
			line = reg.ReplaceAllString(line, "")
			if line != "" {
				hosts = append(hosts, line)
			}
			break
		} else {
			fmt.Println(err)
			os.Exit(1)
		}
	}
	return hosts
}

func parseHosts(ip, hostFile, csvFile string) ([]string, []hostInfo, error) {
	var hosts []string
	var csvHosts []hostInfo
	// 解析主机列表
	if csvFile != "" {
		var err error
		csvHosts, err = readCSVFile(csvFile)
		if err != nil {
			return nil, nil, fmt.Errorf("读取CSV文件失败: %v", err)
		}
	} else {
		if ip != "" {
			hosts = strings.Split(ip, ",")
		} else if hostFile != "" {
			hosts = bufferedReadIpFile(hostFile)
		}
		for _, host := range hosts {
			if !utils.IsValidIPv4(host) {
				return nil, nil, fmt.Errorf("非法的ip地址: %s", host)
			}
		}
	}
	return hosts, csvHosts, nil
}

func ExecuteConcurrently(hosts []string, csvHosts []hostInfo, cmd utils.Command, concurrency int) {
	sem := make(chan struct{}, concurrency)
	wg := sync.WaitGroup{}
	currentOsUser := ""
	if u := utils.GetCurrentUser(); u != "" {
		currentOsUser = u
		utils.Logger.Debug(fmt.Sprintf("当前系统用户: %s", currentOsUser))
	}
	passwords, err := utils.LoadPasswords()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load passwords: %v\n", err)
		passwords = utils.NewPasswordStore()
	}

	passwordModified := false

	executeHost := func(h string, u string, p string) {

		sem <- struct{}{}
		defer func() { <-sem }()

		hostPassword := p
		if hostPassword == "" {

			if storedPass, ok := passwords.GetPass(u, h); ok {
				hostPassword = storedPass
			} else {
				// 如果没有保存的密码，从终端读取
				if newPass, err := utils.ReadPasswordFromTerminal(fmt.Sprintf("请输入 %s@%s 的密码: ", u, h)); err == nil {
					hostPassword = newPass
				} else {
					fmt.Fprintf(os.Stderr, "读取密码失败: %v\n", err)
				}
			}

		}

		if suPwd == "" {
			suPwd = hostPassword
		}

		c := utils.SSHCli{
			Host:  h,
			Port:  port,
			User:  u,
			Pwd:   hostPassword,
			SuPwd: suPwd,
		}
		err := c.Connect()
		if err != nil {
			fmt.Printf("[ERROR] %s\n------------\n", h)
			fmt.Fprintf(os.Stderr, "连接到主机 %s 失败: %v\n", h, err)
			return
		}
		defer c.Close()

		// 如果有密码并且是新密码，保存它
		if hostPassword != "" {
			passwordModified = passwords.SaveOrUpdate(u, h, hostPassword)
		}

		result, err := cmd.Execute(&c)
		if err != nil {
			fmt.Printf("[ERROR] %s\n------------\n", h)
			fmt.Fprintf(os.Stderr, "执行命令失败: %v\n%s", err, result)
		} else {
			fmt.Printf("[SUCCESS] %s\n------------\n%s", h, result)
		}
	}

	if len(csvHosts) > 0 {
		// 使用CSV文件中的认证信息
		for _, host := range csvHosts {
			wg.Go(func() { executeHost(host.ip, host.user, host.password) }) // 1.25新特性,不支持低版本
		}
	} else {
		// 使用命令行参数中的认证信息
		for _, h := range hosts {
			if user == "" {
				if currentOsUser == "" {
					fmt.Fprintf(os.Stderr, "未指定用户,且当前系统用户无法获取\n")
					os.Exit(1)
				}
				wg.Go(func() { executeHost(h, currentOsUser, password) })
			} else {
				wg.Go(func() { executeHost(h, user, password) })
			}
		}
	}
	wg.Wait()

	if passwordModified {
		if err := passwords.Save2File(); err != nil {
			fmt.Fprintf(os.Stderr, "保存密码到文件失败: %v", err)
		} else {
			utils.Logger.Info(fmt.Sprintf("密码已保存到文件: %s@%s", user, ip))
		}
	}
}

// func createSSHClient(host string) (*ssh.Client, error) {
// 	config := &ssh.ClientConfig{
// 		User: user,
// 		Auth: []ssh.AuthMethod{
// 			ssh.Password(password),
// 		},
// 		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
// 		Timeout:         10 * time.Second,
// 	}
// 	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
// }

// func execCommand(host, command string) (string, error) {
// 	client, err := createSSHClient(host)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer client.Close()

// 	session, err := client.NewSession()
// 	if err != nil {
// 		return "", err
// 	}
// 	defer session.Close()

// 	output, err := session.CombinedOutput(command)
// 	return string(output), err
// }

func init() {
	rootCmd.AddCommand(execCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	execCmd.Flags().StringVarP(&ip, "ip", "i", "", "需要执行命令的主机,使用英文逗号分隔,和ifile及csv只能选择一个")
	execCmd.Flags().Uint16Var(&port, "port", 22, "ssh端口")
	execCmd.Flags().StringVarP(&command, "cmd", "c", "", "待执行命令,和cfile及shell只能选择一个")
	execCmd.Flags().StringVarP(&user, "user", "u", "", "ssh用户")
	execCmd.Flags().StringVarP(&password, "passwd", "p", "", "ssh密码")
	execCmd.Flags().StringVarP(&hostFile, "ifile", "I", "", "记录需要执行命令的主机的文件的路径,每个ip一行")
	execCmd.Flags().StringVarP(&csvFile, "csv", "", "", "CSV文件路径,包含主机IP,用户名,密码,每行一条记录")
	execCmd.Flags().StringVarP(&cmdFile, "cfile", "C", "", "记录需要执行的脚本文件的路径")
	execCmd.Flags().StringVarP(&shellFile, "shell", "s", "", "需要执行的脚本文件的位置")
	execCmd.Flags().BoolP("sudo", "S", false, "是否需要使用sudo切换到root执行,不要在命令中加入sudo")
	execCmd.Flags().Bool("su", false, "是否需要使用su切换到root用户再执行,不要在命令中加入sudo")
	execCmd.Flags().StringVar(&suPwd, "suPwd", "", "切换到root用户的密码")
	execCmd.MarkFlagsOneRequired("ip", "ifile", "csv")
	execCmd.MarkFlagsMutuallyExclusive("ip", "ifile", "csv")
	execCmd.MarkFlagsOneRequired("cmd", "cfile", "shell")
	execCmd.MarkFlagsMutuallyExclusive("cmd", "cfile", "shell")
	execCmd.MarkFlagsMutuallyExclusive("sudo", "su")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// execCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
