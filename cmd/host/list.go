package host

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
)

func NewCmdInventoryList() *cobra.Command {
	var tagFilter string
	cmd := &cobra.Command{
		Use:   "list",
		Short: i18n.T("inventory_list_short"),
		Run: func(cmd *cobra.Command, args []string) {
			_, provider, _, err := utils.GetConfigStore()
			if err != nil {
				logger.PrintError(i18n.Tf("config_load_error", map[string]any{"Error": err}))
				return
			}

			var nodes map[string]models.Node
			if tagFilter != "" {
				nodes = provider.GetNodesByTag(tagFilter)
			} else {
				nodes = provider.ListNodes()
			}

			if len(nodes) == 0 {
				if tagFilter != "" {
					logger.PrintWarn(i18n.Tf("node_no_tag_match", map[string]any{"Tag": tagFilter}))
				} else {
					logger.PrintWarn(i18n.T("node_no_stored"))
				}
				return
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			_, _ = fmt.Fprintln(w, i18n.T("node_list_header"))

			keys := make([]string, 0, len(nodes))
			for k := range nodes {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, nodeID := range keys {
				node := nodes[nodeID]
				host, _ := provider.GetHost(nodeID)
				identity, _ := provider.GetIdentity(nodeID)

				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					nodeID,
					strings.Join(node.Alias, ", "),
					fmt.Sprintf("%s:%d", host.Address, host.Port),
					identity.User,
					identity.AuthType,
					node.ProxyJump,
					strings.Join(node.Tags, ", "),
				)
			}
			_ = w.Flush()
		},
	}
	cmd.Flags().StringVarP(&tagFilter, "tag", "t", "", i18n.T("flag_inv_tag_filter"))
	return cmd
}

func NewCmdInventoryTags() *cobra.Command {
	return &cobra.Command{
		Use:   "tags",
		Short: i18n.T("inventory_tags_short"),
		Run: func(cmd *cobra.Command, args []string) {
			_, provider, _, err := utils.GetConfigStore()
			if err != nil {
				logger.PrintError(i18n.Tf("config_load_error", map[string]any{"Error": err}))
				return
			}

			nodes := provider.ListNodes()
			tagMap := make(map[string]int)
			for _, node := range nodes {
				for _, tag := range node.Tags {
					tagMap[tag]++
				}
			}

			if len(tagMap) == 0 {
				logger.PrintWarn(i18n.T("tags_no_stored"))
				return
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			_, _ = fmt.Fprintln(w, i18n.T("tags_list_header"))

			tags := make([]string, 0, len(tagMap))
			for t := range tagMap {
				tags = append(tags, t)
			}
			sort.Strings(tags)

			for _, t := range tags {
				_, _ = fmt.Fprintf(w, "%s\t%d\n", t, tagMap[t])
			}
			_ = w.Flush()
		},
	}
}
