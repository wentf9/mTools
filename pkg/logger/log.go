package logger

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// LogLevel 控制全局日志级别
var LogLevel *slog.LevelVar

// underlyingLogger 保留底层的完整 slog 实例，仅用于 Debug 级别等详尽输出
var underlyingLogger *slog.Logger

// 终端颜色常量
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
)

func init() {
	LogLevel = &slog.LevelVar{}
	opts := &slog.HandlerOptions{
		Level: LogLevel, // 默认级别将被 SetLogLevel 覆盖
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == "time" {
				return slog.Attr{Key: "timestamp", Value: slog.TimeValue(a.Value.Time())}
			}
			return a
		},
	}
	underlyingLogger = slog.New(slog.NewTextHandler(os.Stderr, opts))
	// 初始化为极高数值（静默模式），只有配置了级别的才输出
	LogLevel.Set(slog.Level(100))
}

// SetLogLevel 动态设置日志级别
func SetLogLevel(level string) {
	level = strings.ToLower(level)
	switch level {
	case "debug":
		LogLevel.Set(slog.LevelDebug)
	case "info":
		LogLevel.Set(slog.LevelInfo)
	case "warn":
		LogLevel.Set(slog.LevelWarn)
	case "error":
		LogLevel.Set(slog.LevelError)
	case "none", "":
		LogLevel.Set(slog.Level(100))
	default:
		// 如果提供未知级别，维持静默
		LogLevel.Set(slog.Level(100))
	}
}

// Debug 打印详细调试信息 (保留 slog 完整上下文，输出至 os.Stderr)
func Debug(msg string, args ...any) {
	underlyingLogger.Debug(msg, args...)
}

func Debugf(format string, args ...any) {
	underlyingLogger.Debug(fmt.Sprintf(format, args...))
}

// Info 打印常规信息 (纯净格式，无时间戳等，输出至 os.Stdout)
func Info(msg string) {
	if LogLevel.Level() <= slog.LevelInfo {
		fmt.Printf("[%sINFO%s] %s\n", colorBlue, colorReset, msg)
	}
}

func Infof(format string, args ...any) {
	if LogLevel.Level() <= slog.LevelInfo {
		fmt.Printf("[%sINFO%s] %s\n", colorBlue, colorReset, fmt.Sprintf(format, args...))
	}
}

// Success 打印成功信息 (纯净格式，绿色，输出至 os.Stdout)
func Success(msg string) {
	if LogLevel.Level() <= slog.LevelInfo {
		fmt.Printf("[%sSUCCESS%s] %s\n", colorGreen, colorReset, msg)
	}
}

func Successf(format string, args ...any) {
	if LogLevel.Level() <= slog.LevelInfo {
		fmt.Printf("[%sSUCCESS%s] %s\n", colorGreen, colorReset, fmt.Sprintf(format, args...))
	}
}

// Warn 打印警告信息 (纯净格式，黄色，输出至 os.Stderr)
func Warn(msg string) {
	if LogLevel.Level() <= slog.LevelWarn {
		fmt.Fprintf(os.Stderr, "[%sWARN%s] %s\n", colorYellow, colorReset, msg)
	}
}

func Warnf(format string, args ...any) {
	if LogLevel.Level() <= slog.LevelWarn {
		fmt.Fprintf(os.Stderr, "[%sWARN%s] %s\n", colorYellow, colorReset, fmt.Sprintf(format, args...))
	}
}

// Error 打印错误信息 (纯净格式，红色，输出至 os.Stderr)
func Error(msg string) {
	if LogLevel.Level() <= slog.LevelError {
		fmt.Fprintf(os.Stderr, "[%sERROR%s] %s\n", colorRed, colorReset, msg)
	}
}

func Errorf(format string, args ...any) {
	if LogLevel.Level() <= slog.LevelError {
		fmt.Fprintf(os.Stderr, "[%sERROR%s] %s\n", colorRed, colorReset, fmt.Sprintf(format, args...))
	}
}

// --- 纯业务打印方法 (屏蔽了 LogLevel，始终直接输出到 Stdout/Stderr) ---

// Print 等同于 fmt.Print，但受终端规范管控（预留空间）
func Print(args ...any) {
	fmt.Print(args...)
}

// Printf 等同于 fmt.Printf，无任何前缀和颜色
func Printf(format string, args ...any) {
	fmt.Printf(format, args...)
}

// PrintInfof 打印纯净信息 (带蓝色文本修饰，但无[INFO]此类日志式前缀)
func PrintInfof(format string, args ...any) {
	fmt.Printf("%s%s%s\n", colorBlue, fmt.Sprintf(format, args...), colorReset)
}

// PrintSuccessf 打印成功信号 (带绿色彩色文本修饰，无日志式前缀)
func PrintSuccessf(format string, args ...any) {
	fmt.Printf("%s%s%s\n", colorGreen, fmt.Sprintf(format, args...), colorReset)
}

// PrintWarnf 打印警告信息 (黄色彩色文本修饰，输出给 stderr)
func PrintWarnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s%s%s\n", colorYellow, fmt.Sprintf(format, args...), colorReset)
}

// PrintErrorf 打印纯净错误信号 (带红色彩色文本修饰，输出给 stderr)
func PrintErrorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s%s%s\n", colorRed, fmt.Sprintf(format, args...), colorReset)
}
