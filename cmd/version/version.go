package version

import "fmt"

// 这些变量在编译时会被 ldflags 覆盖
// 默认值用于开发环境（直接 go run 时显示）
var (
	Version   = "dev"     // 版本号 (e.g. v1.0.0)
	Commit    = "none"    // Git Commit Hash
	BuildTime = "unknown" // 编译时间
)

// PrintFullVersion 打印详细版本信息
func PrintFullVersion() {
	fmt.Printf("Version:    %s\n", Version)
	fmt.Printf("Git Commit: %s\n", Commit)
	fmt.Printf("Build Time: %s\n", BuildTime)
}
