package active

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ismailtsdln/ScoutSec/pkg/analysis"
)

// Fuzzer handles the active scanning logic.
type Fuzzer struct {
	TargetURL   string
	Payloads    []Payload
	Detector    *analysis.Detector
	WorkerCount int
	Client      *http.Client
}

// NewFuzzer creates a new instance of Fuzzer.
func NewFuzzer(target string, workerCount int) *Fuzzer {
	return &Fuzzer{
		TargetURL:   target,
		Payloads:    GetDefaultPayloads(), // Start with default payloads
		Detector:    analysis.NewDetector(),
		WorkerCount: workerCount,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Start begins the active scanning process.
func (f *Fuzzer) Start() {
	var wg sync.WaitGroup
	jobs := make(chan Payload, len(f.Payloads))

	// Start workers
	for i := 0; i < f.WorkerCount; i++ {
		wg.Add(1)
		go f.worker(i, jobs, &wg)
	}

	// Send jobs
	for _, p := range f.Payloads {
		jobs <- p
	}
	close(jobs)

	wg.Wait()
	fmt.Println("Active scan completed.")
}

func (f *Fuzzer) worker(id int, jobs <-chan Payload, wg *sync.WaitGroup) {
	defer wg.Done()
	for p := range jobs {
		f.fuzzTarget(p)
	}
}

func (f *Fuzzer) fuzzTarget(p Payload) {
	// Simple query parameter fuzzing for demonstration
	// In a real scenario, this would parse the URL and inject into specific params.

	parsedURL, err := url.Parse(f.TargetURL)
	if err != nil {
		fmt.Printf("Error parsing URL: %v\n", err)
		return
	}

	q := parsedURL.Query()
	// Inject payload into a test parameter called 'test' if none exist, or append to existing?
	// For simplicity, let's just append a fuzz param.
	q.Set("fuzz_param", p.Content)
	parsedURL.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return
	}

	// Add a header to identify scanner (optional)
	req.Header.Set("User-Agent", "ScoutSec/1.0")

	resp, err := f.Client.Do(req)
	if err != nil {
		// Log error but continue
		return
	}
	defer resp.Body.Close()

	// Analyze the response using the existing detector logic
	// We might need to extend Detector to look for reflection of the payload specifically.
	f.Detector.AnalyzeResponse(resp)

	// Check for direct reflection of XSS payload
	// buffer := new(bytes.Buffer)
	// buffer.ReadFrom(resp.Body)
	// body := buffer.String()
	// if strings.Contains(body, p.Content) {
	// 	fmt.Printf("[VULN] Reflected input detected for %s with payload %s\n", p.Name, p.Content)
	// }
}
