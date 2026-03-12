package cmd

import (
	"net"
	"sync"

	"example.com/MikuTools/pkg/logger"
	"github.com/spf13/cobra"
)

// dnsCmd represents the dns command
var dnsCmd = &cobra.Command{
	Use:   "dns domain1 domain2 ...",
	Short: "dns查询",
	Long:  `dns查询`,

	Run: func(cmd *cobra.Command, args []string) {
		wg := sync.WaitGroup{}
		for _, domain := range args {
			wg.Add(1)           // Add this line to correctly use WaitGroup
			go func(d string) { // Pass domain as argument to goroutine to avoid loop variable capture
				defer wg.Done()
				if resolve, err := net.ResolveIPAddr("ip", d); err != nil {
					logger.PrintErrorf("主机名 [%s] 无法解析为ip地址: %v", d, err)
				} else {
					logger.PrintInfof("主机名 [%s] 的IP地址为: [%s]", d, resolve.String())
				}
			}(domain)
		}
		wg.Wait()
	},
}

func init() {
	rootCmd.AddCommand(dnsCmd)
}
