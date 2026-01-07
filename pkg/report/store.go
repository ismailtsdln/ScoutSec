package report

import (
	"sync"
)

var (
	GlobalReport   *Report
	IssueCallbacks []func(Issue) // Global callbacks for all reports
	once           sync.Once
	mu             sync.Mutex
)

// InitReport initializes the global report for the session.
func InitReport(target string, scanType string) {
	once.Do(func() {
		GlobalReport = NewReport(target, scanType)
	})
}

// AddIssue adds a finding to the global report thread-safely.
func AddIssue(issue Issue) {
	if GlobalReport != nil {
		GlobalReport.AddIssue(issue)
	}

	// Also call global callbacks
	mu.Lock()
	callbacks := make([]func(Issue), len(IssueCallbacks))
	copy(callbacks, IssueCallbacks)
	mu.Unlock()

	for _, cb := range callbacks {
		if cb != nil {
			cb(issue)
		}
	}
}

// RegisterCallback adds a new global listener for findings.
func RegisterCallback(cb func(Issue)) {
	mu.Lock()
	defer mu.Unlock()
	IssueCallbacks = append(IssueCallbacks, cb)
}
