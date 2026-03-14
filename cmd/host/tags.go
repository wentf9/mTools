package host

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func NewCmdInventoryTagAdd() *cobra.Command {
	return &cobra.Command{
		Use:   "add [tag_name] [node1,node2...]",
		Short: i18n.T("inventory_tag_add_short"),
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tagName := strings.TrimSpace(args[0])
			nodeNames := strings.Split(args[1], ",")
			if tagName == "" {
				return fmt.Errorf("标签名称不能为空")
			}

			store, provider, cfg, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			updatedCount := 0
			for _, query := range nodeNames {
				name := provider.Find(strings.TrimSpace(query))
				if name == "" {
					continue
				}
				if node, ok := provider.GetNode(name); ok {
					exists := false
					for _, t := range node.Tags {
						if t == tagName {
							exists = true
							break
						}
					}
					if !exists {
						node.Tags = append(node.Tags, tagName)
						provider.AddNode(name, node)
						updatedCount++
					}
				}
			}
			if updatedCount > 0 {
				if err := store.Save(cfg); err != nil {
					return err
				}
				logger.PrintSuccess(i18n.Tf("tag_add_success", map[string]any{"Count": updatedCount, "Tag": tagName}))
			}
			return nil
		},
	}
}

func NewCmdInventoryTagRemove() *cobra.Command {
	return &cobra.Command{
		Use:   "remove [tag_name] [node1,node2...]",
		Short: i18n.T("inventory_tag_remove_short"),
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tagName := strings.TrimSpace(args[0])
			nodeNames := strings.Split(args[1], ",")
			if tagName == "" {
				return fmt.Errorf("标签名称不能为空")
			}

			store, provider, cfg, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			updatedCount := 0
			for _, query := range nodeNames {
				name := provider.Find(strings.TrimSpace(query))
				if name == "" {
					continue
				}
				if node, ok := provider.GetNode(name); ok {
					newTags, found := make([]string, 0), false
					for _, t := range node.Tags {
						if t == tagName {
							found = true
							continue
						}
						newTags = append(newTags, t)
					}
					if found {
						node.Tags = newTags
						provider.AddNode(name, node)
						updatedCount++
					}
				}
			}
			if updatedCount > 0 {
				if err := store.Save(cfg); err != nil {
					return err
				}
				logger.PrintSuccess(i18n.Tf("tag_remove_success", map[string]any{"Count": updatedCount, "Tag": tagName}))
			}
			return nil
		},
	}
}
