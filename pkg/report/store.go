package report

import (
	"sync"
	"time"
)

var (
	GlobalReport *Report
	once         sync.Once
	mu           sync.Mutex
)

// InitReport initializes the global report for the session.
func InitReport(target string, scanType string) {
	once.Do(func() {
		GlobalReport = &Report{
			Target:   target,
			ScanTime: time.Now(),
			ScanType: scanType,
			Issues:   []Issue{},
		}
	})
}

// AddIssue adds a finding to the global report thread-safely.
func AddIssue(issue Issue) {
	mu.Lock()
	defer mu.Unlock()
	if GlobalReport != nil {
		GlobalReport.Issues = append(GlobalReport.Issues, issue)
	}
}
