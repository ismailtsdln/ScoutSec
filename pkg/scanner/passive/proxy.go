package passive

import (
	"log"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/ismailtsdln/ScoutSec/pkg/analysis"
)

// ProxyScanner handles the passive scanning via an HTTP proxy.
type ProxyScanner struct {
	ProxyAddr string
	Detector  *analysis.Detector
}

// NewProxyScanner creates a new instance of ProxyScanner.
func NewProxyScanner(addr string) *ProxyScanner {
	return &ProxyScanner{
		ProxyAddr: addr,
		Detector:  analysis.NewDetector(),
	}
}

// Start starts the proxy server and listens for traffic.
func (p *ProxyScanner) Start() error {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

	// Intercept requests
	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			// Analyze request for potential issues (e.g., missing headers, weird params)
			p.Detector.AnalyzeRequest(r)
			return r, nil
		})

	// Intercept responses
	proxy.OnResponse().DoFunc(
		func(r *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if r != nil {
				// Analyze response for information leakage, errors, etc.
				p.Detector.AnalyzeResponse(r)
			}
			return r
		})

	log.Printf("Starting passive proxy on %s", p.ProxyAddr)
	return http.ListenAndServe(p.ProxyAddr, proxy)
}
