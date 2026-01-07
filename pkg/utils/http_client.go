package utils

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// HTTPClient is a wrapper around http.Client with rate limiting and retry logic.
type HTTPClient struct {
	Client      *http.Client
	RateLimiter *rate.Limiter
	Retries     int
	Timeout     time.Duration
}

// NewHTTPClient creates a new HTTPClient.
func NewHTTPClient(reqPerSec int, timeout time.Duration, retries int) *HTTPClient {
	return &HTTPClient{
		Client:      &http.Client{Timeout: timeout},
		RateLimiter: rate.NewLimiter(rate.Limit(reqPerSec), 1), // Burst of 1
		Retries:     retries,
		Timeout:     timeout,
	}
}

// Do performs an HTTP request with rate limiting and retries.
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	ctx := context.Background()

	// Wait for rate limiter
	if err := c.RateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	var resp *http.Response
	var err error

	for i := 0; i <= c.Retries; i++ {
		resp, err = c.Client.Do(req)
		if err != nil {
			// Network error, retry
			time.Sleep(backoffContext(i))
			continue
		}

		// Check for retryable status codes
		if isRetryable(resp.StatusCode) {
			resp.Body.Close()
			time.Sleep(backoffContext(i))
			continue
		}

		// Success or non-retryable error
		return resp, nil
	}

	return nil, fmt.Errorf("max retries reached: %v", err)
}

func isRetryable(code int) bool {
	switch code {
	case 429, 500, 502, 503, 504:
		return true
	}
	return false
}

func backoffContext(attempt int) time.Duration {
	return time.Duration(1<<attempt) * time.Second
}
