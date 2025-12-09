package global

import (
	"golang.org/x/term"
)

var (
	IsTerminal bool = term.IsTerminal(0) //是否是交互式环境,false表示可能是管道或重定向
)

func init() {
}
