package report

import (
	"sync"
	"time"
)

var (
	GlobalReport   *Report
	IssueCallbacks []func(Issue)
	once           sync.Once
	mu             sync.Mutex
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
	if GlobalReport != nil {
		GlobalReport.Issues = append(GlobalReport.Issues, issue)
	}
	// Copy slice under lock to iterate safely
	callbacks := make([]func(Issue), len(IssueCallbacks))
	copy(callbacks, IssueCallbacks)
	mu.Unlock()

	// Call all callbacks outside the report lock
	for _, cb := range callbacks {
		if cb != nil {
			cb(issue)
		}
	}
}

// RegisterCallback adds a new listener for findings.
func RegisterCallback(cb func(Issue)) {
	mu.Lock()
	defer mu.Unlock()
	IssueCallbacks = append(IssueCallbacks, cb)
}
