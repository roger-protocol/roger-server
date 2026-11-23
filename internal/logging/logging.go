package logging

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
)

type loggerCtxKey struct{}

func New(level string, format string) *slog.Logger {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: slogLevel}
	var handler slog.Handler

	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}

func LoggerFromContext(ctx context.Context) *slog.Logger {
	if loggerStore, ok := ctx.Value(loggerCtxKey{}).(*atomic.Pointer[slog.Logger]); ok && loggerStore != nil {
		if logger := loggerStore.Load(); logger != nil {
			return logger
		}
	}
	return slog.Default()
}

func NewContextWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	loggerStore := &atomic.Pointer[slog.Logger]{}
	loggerStore.Store(logger)
	return context.WithValue(ctx, loggerCtxKey{}, loggerStore)
}

func With(ctx context.Context, args ...any) context.Context {
	if loggerStore, ok := ctx.Value(loggerCtxKey{}).(*atomic.Pointer[slog.Logger]); ok && loggerStore != nil {
		if oldLogger := loggerStore.Load(); oldLogger != nil {
			if loggerStore.CompareAndSwap(oldLogger, oldLogger.With(args...)) {
				return ctx
			}
		}
	}
	return NewContextWithLogger(ctx, slog.Default().With(args...))
}
