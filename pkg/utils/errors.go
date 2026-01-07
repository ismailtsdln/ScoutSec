package utils

import (
	"fmt"
	"runtime/debug"
)

// RecoverPanic recovers from panics and logs the error.
func RecoverPanic() {
	if r := recover(); r != nil {
		fmt.Printf("[PANIC RECOVERED] %v\n", r)
		fmt.Printf("Stack trace:\n%s\n", debug.Stack())
	}
}

// SafeExecute wraps a function with panic recovery.
func SafeExecute(fn func() error, context string) error {
	defer RecoverPanic()

	err := fn()
	if err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}
