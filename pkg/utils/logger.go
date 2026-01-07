package utils

import (
	"log"
	"os"
)

// Logger is a wrapper around the standard logger or a structured logger.
// For now, we'll use a simple wrapper, but this can be swapped for Zap or Logrus.
type Logger struct {
	*log.Logger
}

func NewLogger() *Logger {
	return &Logger{
		Logger: log.New(os.Stdout, "[ScoutSec] ", log.LstdFlags),
	}
}

func (l *Logger) Info(msg string) {
	l.Println("INFO: " + msg)
}

func (l *Logger) Error(msg string) {
	l.Println("ERROR: " + msg)
}
