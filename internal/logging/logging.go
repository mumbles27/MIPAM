package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// File adds JSON file output for service managers that do not capture stderr.
// Rotation is an operator responsibility; restart after moving the log file.
func File(path string) (io.Closer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(io.MultiWriter(os.Stderr, f), nil)))
	return f, nil
}
