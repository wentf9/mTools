package utils

import (
	"log/slog"
	"os"
	"strings"
)

type Log struct {
	*slog.LevelVar
	*slog.Logger
}

// Logger is the global logger instance
var Logger *Log

func init() {
	logLevel := &slog.LevelVar{}
	opts := &slog.HandlerOptions{
		Level: logLevel, // Set the default log level to Error
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
	Logger = &Log{
		LevelVar: logLevel, // Default log level
		Logger:   slog.New(slog.NewTextHandler(os.Stdout, opts)),
	}
	Logger.SetLogLevel("error") // Set default log level to Error
}

func (l *Log) SetLogLevel(level string) {
	// Update the global logger's level
	level = strings.ToLower(level)
	switch level {
	case "debug":
		l.Set(slog.LevelDebug)
	case "info":
		l.Set(slog.LevelInfo)
	case "warn":
		l.Set(slog.LevelWarn)
	case "error":
		l.Set(slog.LevelError)
	}
}

func (l *Log) Fatal(msg string, args ...any) {
	l.Error(msg, args...)
	os.Exit(1) // Exit the program with a non-zero status
}
