package utils

import (
	"fmt"

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

func init() {
	if !IsLinux() {
		global.IsTerminal = true
	}
}
