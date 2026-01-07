package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	// 5 requests per second
	client := NewHTTPClient(5, 1*time.Second, 0)

	start := time.Now()
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		client.RateLimiter.Wait(req.Context())
	}
	elapsed := time.Since(start)

	// Ideally should take at least 800ms for 5 reqs at 5/s (burst 1 means 1st is instant, then 4 more spaced by 200ms)
	// 4 * 200ms = 800ms.
	if elapsed < 800*time.Millisecond {
		t.Errorf("Rate limiter too fast, took %v", elapsed)
	}
}

func TestRetryLogic(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewHTTPClient(10, 1*time.Second, 2) // 2 retries -> 3 attempts total

	req, _ := http.NewRequest("GET", server.URL, nil)
	_, err := client.Do(req)

	if err != nil {
		// Expected to fail after retries
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}
