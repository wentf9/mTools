package utils

import (
	"log/slog"
	"os"
	"strings"
)

// Logger is the global logger instance
var Logger *slog.Logger
var LogLevel *slog.LevelVar

func init() {
	LogLevel = &slog.LevelVar{}
	opts := &slog.HandlerOptions{
		Level: LogLevel, // Set the default log level to Error
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Customize attributes if needed
			if a.Key == "time" {
				return slog.Attr{Key: "timestamp", Value: slog.TimeValue(a.Value.Time())}
			}
			return a
		},
		// Add any other options you need, like encoding, etc.
	}
	// Initialize the global logger with default options
	Logger = slog.New(slog.NewTextHandler(os.Stderr, opts))
	LogLevel.Set(slog.LevelError) // Set default log level to Error
}

func SetLogLevel(level string) {
	// Update the global logger's level
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
	}
}
