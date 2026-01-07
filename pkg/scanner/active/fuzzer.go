package active

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/ismailtsdln/ScoutSec/pkg/analysis"
	"github.com/ismailtsdln/ScoutSec/pkg/utils"
)

// Fuzzer handles the active scanning logic.
type Fuzzer struct {
	TargetURL   string
	Payloads    []Payload
	Detector    *analysis.Detector
	WorkerCount int
	Client      *utils.HTTPClient
}

// NewFuzzer creates a new instance of Fuzzer.
func NewFuzzer(target string, workerCount int, client *utils.HTTPClient) *Fuzzer {
	return &Fuzzer{
		TargetURL:   target,
		Payloads:    GetDefaultPayloads(), // Start with default payloads
		Detector:    analysis.NewDetector(),
		WorkerCount: workerCount,
		Client:      client,
	}
}

// Start begins the active scanning process.
func (f *Fuzzer) Start() {
	var wg sync.WaitGroup
	jobs := make(chan Payload, len(f.Payloads))

	fmt.Printf("[*] Starting active fuzzing with %d payloads...\n", len(f.Payloads))

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
	fmt.Println("\n[✓] Active scan completed.")
}

func (f *Fuzzer) worker(id int, jobs <-chan Payload, wg *sync.WaitGroup) {
	defer wg.Done()
	for p := range jobs {
		f.fuzzTarget(p)
	}
}

func (f *Fuzzer) fuzzTarget(p Payload) {
	parsedURL, err := url.Parse(f.TargetURL)
	if err != nil {
		fmt.Printf("Error parsing URL: %v\n", err)
		return
	}

	// Multi-parameter fuzzing (Discovery)
	queryParams := parsedURL.Query()

	// If no parameters, add a default one for testing
	if len(queryParams) == 0 {
		queryParams.Set("scout_test", "")
	}

	// Mutate the payload
	mutations := MutatePayload(p.Content)

	for param := range queryParams {
		for _, mutation := range mutations {
			// Create a copy of the query params
			fuzzedParams := url.Values{}
			for k, v := range queryParams {
				fuzzedParams[k] = v
			}

			// Inject mutated payload
			fuzzedParams.Set(param, mutation)
			parsedURL.RawQuery = fuzzedParams.Encode()

			req, err := http.NewRequest("GET", parsedURL.String(), nil)
			if err != nil {
				continue
			}

			req.Header.Set("User-Agent", "ScoutSec/2.0 (Advanced)")

			resp, err := f.Client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Analyze the response
			f.Detector.AnalyzeResponse(resp)
		}
	}
}
