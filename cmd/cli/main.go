package main

import (
	"os"
	"strings"

	"github.com/wentf9/xops-cli/cmd"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func main() {
	// 提前解析 --lang 参数，在命令构造前设置语言
	// 解决 Cobra --help 跳过 PersistentPreRun 导致语言设置不生效的问题
	lang := parseLangFromArgs(os.Args[1:])
	i18n.Init(lang)

	cmd.Execute()
}

// parseLangFromArgs 从命令行参数中提取 --lang 值
func parseLangFromArgs(args []string) string {
	for i, arg := range args {
		if arg == "--lang" && i+1 < len(args) {
			return args[i+1]
		}
		if after, ok := strings.CutPrefix(arg, "--lang="); ok {
			return after
		}
	}
	return ""
}
