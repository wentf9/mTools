package main

import (
	"github.com/wentf9/xops-cli/cmd"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func main() {
	i18n.Init("")
	cmd.Execute()
}
