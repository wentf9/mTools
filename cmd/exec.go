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
	sudo      bool
	// keyFile string
)

// execCmd represents the exec command
var execCmd = &cobra.Command{
	Use:   "exec",
	Short: "对多台主机执行命令",
	Long:  `一条命令在多台主机执行`,
	Run: func(cmd *cobra.Command, args []string) {
		var hosts []string
		var csvHosts []hostInfo

		if csvFile != "" {
			var err error
			csvHosts, err = readCSVFile(csvFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "读取CSV文件失败: %v\n", err)
				os.Exit(1)
			}
		} else {
			if ip != "" {
				hosts = strings.Split(ip, ",")
			} else if hostFile != "" {
				hosts = bufferedReadIpFile(hostFile)
			}

			for _, host := range hosts {
				if !utils.IsValidIPv4(host) {
					fmt.Println("错误:非法的ip地址:" + host)
					os.Exit(1)
				}
			}
		}

		concurrency := len(hosts)
		if csvFile != "" {
			concurrency = len(csvHosts)
		}
		ExecuteConcurrently(hosts, csvHosts, command, concurrency)
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

func readCSVFile(path string) ([]hostInfo, error) {
	var hosts []hostInfo
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("无法打开CSV文件: %v", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	firstLine := true

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("读取CSV文件失败: %v", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			if err == io.EOF {
				break
			}
			continue
		}

		// 跳过CSV头行
		if firstLine {
			firstLine = false
			if strings.Contains(strings.ToLower(line), "ip") {
				continue
			}
		}

		// 分割CSV行
		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			return nil, fmt.Errorf("CSV格式错误,每行需要包含: IP,用户名,密码")
		}

		// 移除字段中的引号和空白
		ip := strings.Trim(strings.TrimSpace(fields[0]), "\"'")
		user := strings.Trim(strings.TrimSpace(fields[1]), "\"'")
		password := strings.Trim(strings.TrimSpace(fields[2]), "\"'")

		if !utils.IsValidIPv4(ip) {
			return nil, fmt.Errorf("无效的IP地址: %s", ip)
		}

		hosts = append(hosts, hostInfo{
			ip:       ip,
			user:     user,
			password: password,
		})

		if err == io.EOF {
			break
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("CSV文件中没有找到有效的主机信息")
	}

	return hosts, nil
}

func ExecuteConcurrently(hosts []string, csvHosts []hostInfo, cmd string, concurrency int) {
	sem := make(chan struct{}, concurrency)
	wg := sync.WaitGroup{}
	currentOsUser := ""
	if u := utils.GetCurrentUser(); u != "" {
		currentOsUser = u
		utils.Logger.Debug("当前系统用户: %s", currentOsUser)
	}
	passwords, err := utils.LoadPasswords()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load passwords: %v\n", err)
		passwords = make(utils.PasswordStore)
	}
	var mu sync.Mutex
	passwordModified := false

	executeHost := func(h string, u string, p string) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		hostPassword := p
		if hostPassword == "" {
			mu.Lock()
			if storedPass, ok := passwords.Get(u, h); ok {
				hostPassword = storedPass
			} else {
				// 如果没有保存的密码，从终端读取
				if newPass, err := utils.ReadPasswordFromTerminal(fmt.Sprintf("请输入 %s@%s 的密码: ", u, h)); err == nil {
					hostPassword = newPass
				} else {
					fmt.Fprintf(os.Stderr, "读取密码失败: %v\n", err)
				}
			}
			mu.Unlock()
		}

		c := utils.SSHCli{
			Ip:   h,
			Port: port,
			User: u,
			Pwd:  hostPassword,
			Sudo: sudo,
		}
		_, err := c.Connect()
		if err != nil {
			fmt.Printf("[ERROR] %s\n------------\n", h)
			fmt.Fprintf(os.Stderr, "连接到主机 %s 失败: %v\n", h, err)
			return
		}
		defer c.Client.Close()

		// 如果有密码并且是新密码，保存它
		if hostPassword != "" {
			mu.Lock()
			if storedPass, ok := passwords.Get(u, h); !ok || storedPass != hostPassword {
				if err := passwords.Set(u, h, hostPassword); err == nil {
					passwordModified = true
				} else {
					fmt.Fprintf(os.Stderr, "保存密码失败: %v\n", err)
				}
			}
			mu.Unlock()
		}

		result, err := c.Run(command)
		if err != nil {
			fmt.Printf("[ERROR] %s\n------------\n", h)
			fmt.Fprintf(os.Stderr, "执行命令失败: %v\n", err)
		} else {
			fmt.Printf("[SUCCESS] %s\n------------\n%s", h, result)
		}
	}

	if len(csvHosts) > 0 {
		// 使用CSV文件中的认证信息
		for _, host := range csvHosts {
			wg.Add(1)
			go executeHost(host.ip, host.user, host.password)
		}
	} else {
		// 使用命令行参数中的认证信息
		for _, h := range hosts {
			wg.Add(1)
			if user == "" {
				if currentOsUser == "" {
					fmt.Fprintf(os.Stderr, "未指定用户,且当前系统用户无法获取\n")
					os.Exit(1)
				}
				go executeHost(h, currentOsUser, password)
			} else {
				go executeHost(h, user, password)
			}
		}
	}
	wg.Wait()

	if passwordModified {
		if err := passwords.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to save passwords: %v", err)
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
	execCmd.PersistentFlags().StringVarP(&ip, "ip", "i", "", "需要执行命令的主机,使用英文逗号分隔,和ifile及csv只能选择一个")
	execCmd.PersistentFlags().Uint16Var(&port, "port", 22, "ssh端口")
	execCmd.PersistentFlags().StringVarP(&command, "cmd", "c", "", "待执行命令,和cfile及shell只能选择一个")
	execCmd.PersistentFlags().StringVarP(&user, "user", "u", "", "ssh用户")
	execCmd.PersistentFlags().StringVarP(&password, "passwd", "p", "", "ssh密码")
	execCmd.PersistentFlags().StringVarP(&hostFile, "ifile", "I", "", "记录需要执行命令的主机的文件的路径,每个ip一行")
	execCmd.PersistentFlags().StringVarP(&csvFile, "csv", "", "", "CSV文件路径,包含主机IP,用户名,密码,每行一条记录")
	execCmd.PersistentFlags().StringVarP(&cmdFile, "cfile", "C", "", "记录需要执行的命令的文件的路径")
	execCmd.PersistentFlags().StringVarP(&shellFile, "shell", "s", "", "需要执行的脚本文件的位置")
	execCmd.PersistentFlags().BoolVarP(&sudo, "sudo", "S", false, "是否需要sudo执行,不要在命令中加入sudo")

	execCmd.MarkFlagsOneRequired("ip", "ifile", "csv")
	execCmd.MarkFlagsMutuallyExclusive("ip", "ifile", "csv")
	execCmd.MarkFlagsOneRequired("cmd", "cfile", "shell")
	execCmd.MarkFlagsMutuallyExclusive("cmd", "cfile", "shell")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// execCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
