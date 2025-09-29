package utils

import (
	"fmt"
	"io"
	"os"

	"example.com/MikuTools/global"
	"github.com/spf13/cobra"
)

func AtLeastOneArgs() func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("需要至少一个参数")
		}
		return nil
	}
}

func AtLeastOneArgsIncludePipe() func(cmd *cobra.Command, args []string) error {
	atLeastOneArgs := AtLeastOneArgs()
	return func(cmd *cobra.Command, args []string) error {
		if !global.IsTerminal {
			if global.ArgsFromStdin == "" {
				return fmt.Errorf("从管道或重定向中读取到的参数为空")
			}
			return nil
		}
		return atLeastOneArgs(cmd, args)
	}
}

func init() {
	if !IsLinux() {
		global.IsTerminal = true
	}
	if !global.IsTerminal {
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "从管道或重定向中读取参数失败: %v", err)
		}
		if string(input) == "" {
			fmt.Fprintf(os.Stderr, "从管道或重定向中读取到的参数为空")
		}
		global.ArgsFromStdin = string(input)
	}
}
