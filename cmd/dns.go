package cmd

import (
	"fmt"
	"net"
	"sync"

	"github.com/spf13/cobra"
)

// dnsCmd represents the loadPwd command
var dnsCmd = &cobra.Command{
	Use:   "dns domain1 domain2 ...",
	Short: "dns查询",
	Long:  `dns查询`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		wg := sync.WaitGroup{}
		for _, domain := range args {
			wg.Go(func() {
				if resolve, err := net.ResolveIPAddr("ip", domain); err != nil {
					fmt.Printf("主机名 [%s] 无法解析为ip地址: %v", domain, err)
				} else {
					fmt.Printf("主机名 [%s] 的IP地址为: [%s]\n", domain, resolve.String())
				}
			})
		}
		wg.Wait()
	},
}

func init() {
	rootCmd.AddCommand(dnsCmd)
}
