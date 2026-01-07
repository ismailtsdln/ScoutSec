package auth

import (
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// SessionManager handles authentication sessions and cookie/header management.
type SessionManager struct {
	Client  *http.Client
	Headers map[string]string
	mu      sync.RWMutex
}

// NewSessionManager creates a new session manager with cookie jar.
func NewSessionManager() (*SessionManager, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}

	return &SessionManager{
		Client: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
		},
		Headers: make(map[string]string),
	}, nil
}

// SetHeader adds a persistent header to all requests.
func (sm *SessionManager) SetHeader(key, value string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.Headers[key] = value
}

// GetHeader retrieves a stored header value.
func (sm *SessionManager) GetHeader(key string) string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.Headers[key]
}

// Do performs an HTTP request with session headers and cookie management.
func (sm *SessionManager) Do(req *http.Request) (*http.Response, error) {
	sm.mu.RLock()
	for key, value := range sm.Headers {
		req.Header.Set(key, value)
	}
	sm.mu.RUnlock()

	return sm.Client.Do(req)
}

// Get performs a GET request with session management.
func (sm *SessionManager) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return sm.Do(req)
}
