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
	"github.com/wentf9/xops-cli/pkg/i18n"
	"golang.org/x/term"
)

type encodeOpts struct {
	isDecode  bool
	stdinData string
}

func newCmdEncode() *cobra.Command {
	opts := &encodeOpts{}

	cmd := &cobra.Command{
		Use:   "encode [command] [-d] args",
		Short: i18n.T("encode_short"),
		Long:  i18n.T("encode_long"),
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	cmd.AddCommand(newEncodeUrlCmd(opts))
	cmd.AddCommand(newEncodeUnicodeCmd(opts))
	cmd.AddCommand(newEncodeUtf8Cmd(opts))
	cmd.AddCommand(newEncodeBase64Cmd(opts))

	cmd.PersistentFlags().BoolVarP(&opts.isDecode, "decode", "d", false, i18n.T("flag_decode"))

	return cmd
}

func newEncodeUrlCmd(opts *encodeOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "url [-d] args",
		Short: i18n.T("url_short"),
		Long:  i18n.T("url_long"),
		Args:  func(cmd *cobra.Command, args []string) error { return argsValidator(args, &opts.stdinData) },
		Run: func(cmd *cobra.Command, args []string) {
			args = prepareArgs(args, opts.stdinData)
			for _, str := range args {
				if opts.isDecode {
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
}

func newEncodeBase64Cmd(opts *encodeOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "base64 [-d] args",
		Short: i18n.T("base64_short"),
		Long:  i18n.T("base64_long"),
		Args:  func(cmd *cobra.Command, args []string) error { return argsValidator(args, &opts.stdinData) },
		Run: func(cmd *cobra.Command, args []string) {
			urlMode, _ := cmd.Flags().GetBool("url")
			args = prepareArgs(args, opts.stdinData)
			if urlMode {
				runBase64(args, opts.isDecode, base64.URLEncoding)
			} else {
				runBase64(args, opts.isDecode, base64.StdEncoding)
			}
		},
	}
	cmd.Flags().BoolP("url", "u", false, i18n.T("flag_base64_url"))
	return cmd
}

func runBase64(args []string, isDecode bool, enc *base64.Encoding) {
	if isDecode {
		for _, str := range args {
			if out, err := enc.DecodeString(str); err != nil {
				fmt.Fprintln(os.Stderr, err)
			} else {
				fmt.Println(string(out))
			}
		}
	} else {
		for _, str := range args {
			fmt.Println(enc.EncodeToString([]byte(str)))
		}
	}
}

func newEncodeUtf8Cmd(opts *encodeOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "utf8 [-d] args",
		Short: i18n.T("utf8_short"),
		Long:  i18n.T("utf8_long"),
		Args:  func(cmd *cobra.Command, args []string) error { return argsValidator(args, &opts.stdinData) },
		Run: func(cmd *cobra.Command, args []string) {
			args = prepareArgs(args, opts.stdinData)
			for _, str := range args {
				if opts.isDecode {
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
}

func newEncodeUnicodeCmd(opts *encodeOpts) *cobra.Command {
	return &cobra.Command{
		Use:   "unicode [-d] args",
		Short: i18n.T("unicode_short"),
		Long:  i18n.T("unicode_long"),
		Args:  func(cmd *cobra.Command, args []string) error { return argsValidator(args, &opts.stdinData) },
		Run: func(cmd *cobra.Command, args []string) {
			args = prepareArgs(args, opts.stdinData)
			for _, str := range args {
				if opts.isDecode {
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
}

func prepareArgs(args []string, stdinData string) []string {
	if len(args) == 0 && stdinData != "" {
		return []string{stdinData}
	}
	return args
}

func argsValidator(args []string, stdinData *string) error {
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

	*stdinData = string(input)
	if *stdinData == "" && len(args) < 1 {
		return fmt.Errorf("需要至少一个参数")
	}
	return nil
}

func stringToUnicode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r <= 0xFFFF {
			fmt.Fprintf(&result, "\\u%04x", r)
		} else {
			// 处理超过U+FFFF的字符（如emoji）
			fmt.Fprintf(&result, "\\U%08x", r)
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
		return "", fmt.Errorf("无效的Unicode序列: %w", err)
	}
	return result, nil
}

// 将字符串转换为UTF-8编码（&#x...;格式）
func stringToUTF8(s string) string {
	var result strings.Builder
	for _, r := range s {
		fmt.Fprintf(&result, "&#x%X;", r)
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
