package browser

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/chromedp/chromedp"
)

// Scanner handles headless browser interactions.
type Scanner struct {
	Timeout time.Duration
}

// NewScanner creates a new browser scanner.
func NewScanner(timeout time.Duration) *Scanner {
	return &Scanner{
		Timeout: timeout,
	}
}

// CaptureScreenshot visits a URL and saves a screenshot.
func (s *Scanner) CaptureScreenshot(url, filename string) error {
	ctx, cancel := s.createContext()
	defer cancel()

	var buf []byte
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second), // Wait for render
		chromedp.FullScreenshot(&buf, 90),
	); err != nil {
		return err
	}

	if err := os.WriteFile(filename, buf, 0644); err != nil {
		return err
	}
	fmt.Printf("[+] Screenshot saved to %s\n", filename)
	return nil
}

// ScanDOMXSS attempts to check for DOM XSS sources/sinks.
// This is a simplified check that looks for execution of a JS payload that writes to DOM.
func (s *Scanner) ScanDOMXSS(url string, payload string) (bool, error) {
	ctx, cancel := s.createContext()
	defer cancel()

	// Inject payload into URL fragment or query param if not present
	target := url + "#" + payload

	var res string
	err := chromedp.Run(ctx,
		chromedp.Navigate(target),
		chromedp.Sleep(1*time.Second),
		// Check if payload execution modified the title or a specific global var
		chromedp.Evaluate(`document.title`, &res),
	)
	if err != nil {
		return false, err
	}

	// This is a very naive check; real DOM XSS scanning is complex.
	// We might check if our payload (e.g., changing title) worked.
	return false, nil // Placeholder return
}

func (s *Scanner) createContext() (context.Context, context.CancelFunc) {
	// Create allocator options (headless, disable gpu, etc.)
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	// We don't defer cancelAlloc here because we want it to live as long as the derived context.
	// But actually, for per-task, we should probably wrap it differently.
	// For simplicity in this tool, we create a fresh one each time or share a global one.
	// Let's create fresh for isolation.

	ctx, cancel := chromedp.NewContext(allocCtx)

	// Wrap with timeout
	ctx, cancelTimeout := context.WithTimeout(ctx, s.Timeout)

	return ctx, func() {
		cancelTimeout()
		cancel()
		cancelAlloc()
	}
}

// Crawl visits a URL and extracts all href links from <a> tags.
func (s *Scanner) Crawl(url string) ([]string, error) {
	ctx, cancel := s.createContext()
	defer cancel()

	var links []string
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second), // Allow SPA to render
		chromedp.Evaluate(`Array.from(document.querySelectorAll('a')).map(a => a.href)`, &links),
	)
	if err != nil {
		return nil, err
	}
	return links, nil
}
