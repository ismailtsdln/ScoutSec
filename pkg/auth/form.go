package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
)

// FormAuth handles form-based authentication automation.
type FormAuth struct {
	Timeout time.Duration
}

// NewFormAuth creates a new form authentication handler.
func NewFormAuth(timeout time.Duration) *FormAuth {
	return &FormAuth{
		Timeout: timeout,
	}
}

// LoginFormConfig defines a login form configuration.
type LoginFormConfig struct {
	LoginURL         string
	UsernameSelector string
	PasswordSelector string
	SubmitSelector   string
	Username         string
	Password         string
	SuccessIndicator string // CSS selector to verify successful login
}

// Login performs automated form-based login.
func (fa *FormAuth) Login(config LoginFormConfig) error {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, fa.Timeout)
	defer cancel()

	// Perform login
	err := chromedp.Run(ctx,
		chromedp.Navigate(config.LoginURL),
		chromedp.Sleep(1*time.Second),
		chromedp.SendKeys(config.UsernameSelector, config.Username),
		chromedp.SendKeys(config.PasswordSelector, config.Password),
		chromedp.Click(config.SubmitSelector),
		chromedp.Sleep(2*time.Second),
	)
	if err != nil {
		return fmt.Errorf("login automation failed: %w", err)
	}

	// Verify success if indicator provided
	if config.SuccessIndicator != "" {
		var exists bool
		err = chromedp.Run(ctx,
			chromedp.Evaluate(fmt.Sprintf(
				`document.querySelector('%s') !== null`,
				config.SuccessIndicator,
			), &exists),
		)
		if err != nil || !exists {
			return fmt.Errorf("login verification failed")
		}
	}

	fmt.Println("[Auth] Form-based login successful")
	return nil
}
