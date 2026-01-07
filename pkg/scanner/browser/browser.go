package browser

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/ismailtsdln/ScoutSec/pkg/report"
)

// Scanner handles headless browser interactions.
type Scanner struct {
	Timeout time.Duration
	Report  *report.Report
}

// NewScanner creates a new browser scanner.
func NewScanner(timeout time.Duration, rep *report.Report) *Scanner {
	return &Scanner{
		Timeout: timeout,
		Report:  rep,
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
func (s *Scanner) ScanDOMXSS(url string) (bool, error) {
	ctx, cancel := s.createContext()
	defer cancel()

	// Payloads to test for DOM XSS
	payloads := []string{
		"<script>document.title='DOMXSS'</script>",
		"javascript:document.title='DOMXSS'",
	}

	for _, p := range payloads {
		target := url + "#" + p
		var title string
		err := chromedp.Run(ctx,
			chromedp.Navigate(target),
			chromedp.Sleep(2*time.Second),
			chromedp.Evaluate(`document.title`, &title),
		)
		if err != nil {
			continue
		}

		if title == "DOMXSS" {
			issue := report.Issue{
				Name:        "DOM-based XSS Detected",
				Description: "Application executes JavaScript from the URL fragment (sink: document.title).",
				Severity:    "High",
				URL:         url,
				Evidence:    fmt.Sprintf("Payload %s successfully modified document title", p),
			}
			if s.Report != nil {
				s.Report.AddIssue(issue)
			} else {
				report.AddIssue(issue)
			}
			return true, nil
		}
	}

	return false, nil
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
func (s *Scanner) Crawl(url string, maxDepth int) ([]string, error) {
	visited := make(map[string]bool)
	var allLinks []string
	s.recursiveCrawl(url, 0, maxDepth, visited, &allLinks)
	return allLinks, nil
}

func (s *Scanner) recursiveCrawl(url string, depth, maxDepth int, visited map[string]bool, allLinks *[]string) {
	if depth > maxDepth || visited[url] {
		return
	}
	visited[url] = true
	*allLinks = append(*allLinks, url)

	ctx, cancel := s.createContext()
	defer cancel()

	var links []string
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('a')).map(a => a.href)`, &links),
	)
	if err != nil {
		return
	}

	for _, link := range links {
		// Only stay within same domain/base for safety in this crawler
		if strings.HasPrefix(link, s.TargetBase(url)) {
			s.recursiveCrawl(link, depth+1, maxDepth, visited, allLinks)
		}
	}
}

func (s *Scanner) TargetBase(rawURL string) string {
	u, _ := url.Parse(rawURL)
	return u.Scheme + "://" + u.Host
}
