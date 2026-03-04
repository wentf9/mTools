package host

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"example.com/MikuTools/pkg/models"
	"example.com/MikuTools/cmd/utils"
	"github.com/spf13/cobra"
)

func NewCmdInventoryList() *cobra.Command {
	var tagFilter string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "列出所有存储的节点",
		Run: func(cmd *cobra.Command, args []string) {
			_, provider, _, err := utils.GetConfigStore()
			if err != nil {
				fmt.Printf("加载配置文件失败: %v\n", err)
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
					fmt.Printf("没有找到带有标签 %s 的节点。\n", tagFilter)
				} else {
					fmt.Println("没有找到已存储的节点。")
				}
				return
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "名称/ID\t别名\t主机地址\t用户\t认证方式\t跳板机\t标签")

			keys := make([]string, 0, len(nodes))
			for k := range nodes {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, nodeId := range keys {
				node := nodes[nodeId]
				host, _ := provider.GetHost(nodeId)
				identity, _ := provider.GetIdentity(nodeId)

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					nodeId,
					strings.Join(node.Alias, ", "),
					fmt.Sprintf("%s:%d", host.Address, host.Port),
					identity.User,
					identity.AuthType,
					node.ProxyJump,
					strings.Join(node.Tags, ", "),
				)
			}
			w.Flush()
		},
	}
	cmd.Flags().StringVarP(&tagFilter, "tag", "t", "", "按标签筛选节点")
	return cmd
}

func NewCmdInventoryTags() *cobra.Command {
	return &cobra.Command{
		Use:   "tags",
		Short: "列出所有标签及对应的节点数量",
		Run: func(cmd *cobra.Command, args []string) {
			_, provider, _, err := utils.GetConfigStore()
			if err != nil {
				fmt.Printf("加载配置文件失败: %v\n", err)
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
				fmt.Println("当前没有已定义的标签。")
				return
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "标签\t节点数量")

			tags := make([]string, 0, len(tagMap))
			for t := range tagMap {
				tags = append(tags, t)
			}
			sort.Strings(tags)

			for _, t := range tags {
				fmt.Fprintf(w, "%s\t%d\n", t, tagMap[t])
			}
			w.Flush()
		},
	}
}
