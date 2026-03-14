package version

import (
	"fmt"

	"github.com/wentf9/xops-cli/pkg/i18n"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

func PrintFullVersion() {
	fmt.Println(i18n.Tf("version_label", map[string]any{"Version": Version}))
	fmt.Println(i18n.Tf("commit_label", map[string]any{"Commit": Commit}))
	fmt.Println(i18n.Tf("build_time_label", map[string]any{"BuildTime": BuildTime}))
}
