package cmd

import (
	"net"
	"sync"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func newCmdDns() *cobra.Command {
	return &cobra.Command{
		Use:   "dns domain1 domain2 ...",
		Short: i18n.T("dns_short"),
		Long:  i18n.T("dns_long"),

		Run: func(cmd *cobra.Command, args []string) {
			wg := sync.WaitGroup{}
			for _, domain := range args {
				wg.Add(1)           // Add this line to correctly use WaitGroup
				go func(d string) { // Pass domain as argument to goroutine to avoid loop variable capture
					defer wg.Done()
					if resolve, err := net.ResolveIPAddr("ip", d); err != nil {
						logger.PrintError(i18n.Tf("dns_resolve_error", map[string]any{"Domain": d, "Error": err}))
					} else {
						logger.PrintInfo(i18n.Tf("dns_resolve_info", map[string]any{"Domain": d, "IP": resolve.String()}))
					}
				}(domain)
			}
			wg.Wait()
		},
	}
}
