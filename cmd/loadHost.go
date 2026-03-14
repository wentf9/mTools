package cmd

import (
	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

var loadHostCmd = &cobra.Command{
	Use:   "loadHost [csv_file]",
	Short: i18n.T("loadhost_short"),
	Long:  i18n.T("loadhost_long"),
	RunE:  host.RunInventoryLoad,
}

func init() {
	loadHostCmd.Flags().StringVarP(&host.TemplateFile, "template", "T", "", i18n.T("flag_inv_template"))
	loadHostCmd.Flags().StringVarP(&host.Tag, "tag", "t", "", i18n.T("flag_inv_load_tag"))
	rootCmd.AddCommand(loadHostCmd)
}
