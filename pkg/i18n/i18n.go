package i18n

import (
	"embed"
	"os"
	"strings"
	"sync"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"
)

//go:embed locales/*.yaml
var localeFS embed.FS

var (
	bundle      *i18n.Bundle
	localizer   *i18n.Localizer
	curLang     string
	once        sync.Once
	pendingLang string
)

func ensureInit() {
	once.Do(func() { Init("") })
}

// Init 初始化 i18n，解析语言偏好并加载翻译文件。
// 传入空字符串时自动从环境变量检测。
func Init(lang string) {
	curLang = detectLang(lang)

	bundle = i18n.NewBundle(language.Chinese)
	bundle.RegisterUnmarshalFunc("yaml", yaml.Unmarshal)

	_, _ = bundle.LoadMessageFileFS(localeFS, "locales/active.zh.yaml")
	_, _ = bundle.LoadMessageFileFS(localeFS, "locales/active.en.yaml")

	localizer = i18n.NewLocalizer(bundle, curLang)

	// 标记 once 为已完成，防止 ensureInit() 再次调用 Init("")
	once.Do(func() {})
}

// T 根据 messageID 返回当前语言的翻译文本。
// 找不到时 fallback 到 messageID 本身。
func T(id string) string {
	ensureInit()
	// 应用待切换的语言（解决 --help 时序问题）
	applyPendingLang()
	msg, err := localizer.Localize(&i18n.LocalizeConfig{MessageID: id})
	if err != nil || msg == "" {
		return id
	}
	return msg
}

// Tf 带模板参数的翻译，data 为 map[string]any。
func Tf(id string, data map[string]any) string {
	ensureInit()
	msg, err := localizer.Localize(&i18n.LocalizeConfig{
		MessageID:    id,
		TemplateData: data,
	})
	if err != nil || msg == "" {
		return id
	}
	return msg
}

// Lang 返回当前生效的语言标签。
func Lang() string {
	return curLang
}

// SetLang 切换语言并重建 localizer（用于 --lang flag 覆盖）。
func SetLang(lang string) {
	if lang == "" {
		return
	}
	curLang = normalizeLang(lang)
	localizer = i18n.NewLocalizer(bundle, curLang)
}

// SetPendingLang 设置待切换的语言（在 main 中提前调用）。
// 该函数用于在命令构造前设置语言，解决 --help 时 init() 先于语言设置的问题。
func SetPendingLang(lang string) {
	if lang != "" {
		pendingLang = normalizeLang(lang)
	}
}

// applyPendingLang 应用待切换的语言
func applyPendingLang() {
	if pendingLang != "" && pendingLang != curLang {
		curLang = pendingLang
		localizer = i18n.NewLocalizer(bundle, curLang)
	}
}

func detectLang(explicit string) string {
	if explicit != "" {
		return normalizeLang(explicit)
	}

	for _, key := range []string{"XOPS_LANG", "LANG", "LC_ALL"} {
		if val := os.Getenv(key); val != "" {
			return normalizeLang(val)
		}
	}

	return "zh"
}

func normalizeLang(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	// 去除 .UTF-8 等后缀
	if idx := strings.Index(raw, "."); idx > 0 {
		raw = raw[:idx]
	}
	switch {
	case strings.HasPrefix(raw, "zh"):
		return "zh"
	case strings.HasPrefix(raw, "en"):
		return "en"
	default:
		return "zh"
	}
}
