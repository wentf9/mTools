package host

import (
	"github.com/spf13/cobra"
)

func NewCmdInventory() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "inventory",
		Aliases: []string{"host", "hosts", "inv"},
		Short:   "管理存储的主机和节点信息",
		Long:    `管理存储的主机、身份认证和节点信息。支持列出、添加、修改和删除操作。`,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	cmd.AddCommand(NewCmdInventoryList())
	cmd.AddCommand(NewCmdInventoryAdd())
	cmd.AddCommand(NewCmdInventoryEdit())
	cmd.AddCommand(NewCmdInventoryDelete())
	cmd.AddCommand(NewCmdInventoryTags())
	cmd.AddCommand(NewCmdInventoryTag())

	return cmd
}

func NewCmdInventoryTag() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tag",
		Short: "管理节点的标签",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	cmd.AddCommand(NewCmdInventoryTagAdd())
	cmd.AddCommand(NewCmdInventoryTagRemove())

	return cmd
}
