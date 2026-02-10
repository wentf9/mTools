package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	isDecode  bool
	stdinData string
)

// encodeCmd represents the exec command
var encodeCmd = &cobra.Command{
	Use:   "encode [command] [-d] args",
	Short: "进行各种编解码操作",
	Long:  `对提供的字符串进行编解码操作`,
	// PersistentPreRun: func(cmd *cobra.Command, args []string) {
	// 	rootCmd.PersistentPostRun(rootCmd, args)
	// 	if !isTerminal {
	// 		input, err := io.ReadAll(os.Stdin)
	// 		if err != nil {
	// 			fmt.Fprintf(os.Stderr, "从管道或重定向中读取参数失败: %v\n", err)
	// 			return
	// 		}
	// 		clear(args)
	// 		args = append(args, string(input))
	// 	}
	// },
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// urlCmd represents the exec command
var urlCmd = &cobra.Command{
	Use:   "url [-d] args",
	Short: "进行urlEncode/urlDecode操作",
	Long:  `对提供的字符串进行url编解码操作`,
	Args:  argsValidator,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 && stdinData != "" {
			args = []string{stdinData}
		}
		for _, str := range args {
			if isDecode {
				if out, err := url.QueryUnescape(str); err != nil {
					fmt.Fprintln(os.Stderr, err)
				} else {
					fmt.Println(out)
				}
			} else {
				fmt.Println(url.QueryEscape(str))
			}
		}
	},
}

// base64Cmd represents the exec command
var base64Cmd = &cobra.Command{
	Use:   "base64 [-d] args",
	Short: "进行base64Encode/base64Decode操作",
	Long:  `对提供的字符串进行base64编解码操作`,
	Args:  argsValidator,
	Run: func(cmd *cobra.Command, args []string) {
		urlMode, _ := cmd.Flags().GetBool("url")
		if len(args) == 0 && stdinData != "" {
			args = []string{stdinData}
		}
		if urlMode {
			if isDecode {
				for _, str := range args {
					if out, err := base64.URLEncoding.DecodeString(str); err != nil {
						fmt.Fprintln(os.Stderr, err)
					} else {
						fmt.Println(string(out))
					}
				}
			} else {
				for _, str := range args {
					fmt.Println(base64.URLEncoding.EncodeToString([]byte(str)))
				}
			}
		} else {
			if isDecode {
				for _, str := range args {
					if out, err := base64.StdEncoding.DecodeString(str); err != nil {
						fmt.Fprintln(os.Stderr, err)
					} else {
						fmt.Println(string(out))
					}
				}
			} else {
				for _, str := range args {
					fmt.Println(base64.StdEncoding.EncodeToString([]byte(str)))
				}
			}
		}
	},
}

// utf8Cmd represents the exec command
var utf8Cmd = &cobra.Command{
	Use:   "utf8 [-d] args",
	Short: "进行utf-8编解码操作",
	Long:  `对提供的字符串进行utf-8编解码操作`,
	Args:  argsValidator,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 && stdinData != "" {
			args = []string{stdinData}
		}
		for _, str := range args {
			if isDecode {
				if out, err := utf8ToString(str); err != nil {
					fmt.Fprintln(os.Stderr, err)
				} else {
					fmt.Println(out)
				}
			} else {
				fmt.Println(stringToUTF8(str))
			}
		}
	},
}

// unicodeCmd represents the exec command
var unicodeCmd = &cobra.Command{
	Use:   "unicode [-d] args",
	Short: "进行Unicode编解码操作",
	Long:  `对提供的字符串进行unicode编解码操作`,
	Args:  argsValidator,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 && stdinData != "" {
			args = []string{stdinData}
		}
		for _, str := range args {
			if isDecode {
				if out, err := unicodeToString(str); err != nil {
					fmt.Fprintln(os.Stderr, err)
				} else {
					fmt.Println(out)
				}
			} else {
				fmt.Println(stringToUnicode(str))
			}
		}
	},
}

func argsValidator(cmd *cobra.Command, args []string) error {
	if term.IsTerminal(0) {
		if len(args) < 1 {
			return fmt.Errorf("需要至少一个参数")
		}
		return nil
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("从管道或重定向中读取参数失败: %w", err)
	}

	stdinData = string(input)
	if stdinData == "" && len(args) < 1 {
		return fmt.Errorf("需要至少一个参数")
	}
	return nil
}

func init() {
	rootCmd.AddCommand(encodeCmd)
	encodeCmd.AddCommand(urlCmd)
	encodeCmd.AddCommand(unicodeCmd)
	encodeCmd.AddCommand(utf8Cmd)
	encodeCmd.AddCommand(base64Cmd)

	encodeCmd.PersistentFlags().BoolVarP(&isDecode, "decode", "d", false, "切换到解码模式")

	base64Cmd.Flags().BoolP("url", "u", false, "切换到url模式(base64串中只包含URL安全字符)")
}

func stringToUnicode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r <= 0xFFFF {
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			// 处理超过U+FFFF的字符（如emoji）
			result.WriteString(fmt.Sprintf("\\U%08x", r))
		}
	}
	return result.String()
}

func unicodeToString(s string) (string, error) {
	// 使用json.Unmarshal来处理Unicode转义序列
	str := "\"" + s + "\""
	var result string
	err := json.Unmarshal([]byte(str), &result)
	if err != nil {
		return "", fmt.Errorf("无效的Unicode序列: %v", err)
	}
	return result, nil
}

// 将字符串转换为UTF-8编码（&#x...;格式）
func stringToUTF8(s string) string {
	var result strings.Builder
	for _, r := range s {
		result.WriteString(fmt.Sprintf("&#x%X;", r))
	}
	return result.String()
}

// 将UTF-8编码（&#x...;格式）转换回字符串
func utf8ToString(s string) (string, error) {
	var result strings.Builder
	parts := strings.Split(s, "&#x")

	for i, part := range parts {
		if i == 0 {
			// 第一个部分可能不是编码
			if part != "" && !strings.HasPrefix(s, "&#x") {
				result.WriteString(part)
			}
			continue
		}

		// 查找分号位置
		semicolonPos := strings.Index(part, ";")
		if semicolonPos == -1 {
			return "", fmt.Errorf("无效的UTF-8编码格式: 缺少分号")
		}

		// 提取十六进制数字部分
		hexStr := part[:semicolonPos]
		// 将十六进制字符串转换为整数
		codePoint, err := strconv.ParseInt(hexStr, 16, 32)
		if err != nil {
			return "", fmt.Errorf("无效的十六进制数字: %s", hexStr)
		}

		// 将代码点转换为字符
		result.WriteRune(rune(codePoint))

		// 添加剩余部分（如果有）
		if len(part) > semicolonPos+1 {
			result.WriteString(part[semicolonPos+1:])
		}
	}

	// 如果没有找到任何编码，直接返回原字符串
	if result.Len() == 0 {
		return s, nil
	}

	return result.String(), nil
}
