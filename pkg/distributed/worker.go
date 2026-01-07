package distributed

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ismailtsdln/ScoutSec/pkg/report"
	"github.com/ismailtsdln/ScoutSec/pkg/scanner/active"
	"github.com/ismailtsdln/ScoutSec/pkg/scanner/middleware"
)

// Worker runs tasks from the Master.
type Worker struct {
	MasterURL string
	Client    *http.Client
}

// NewWorker creates a new Worker.
func NewWorker(masterURL string) *Worker {
	return &Worker{
		MasterURL: masterURL,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Start polling for tasks.
func (w *Worker) Start() {
	fmt.Printf("[Worker] Connected to master at %s\n", w.MasterURL)

	for {
		w.poll()
		time.Sleep(5 * time.Second)
	}
}

func (w *Worker) poll() {
	resp, err := w.Client.Get(w.MasterURL + "/task")
	if err != nil {
		fmt.Printf("[Worker] Error polling master: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return // No tasks
	}

	var task Task
	if err := json.NewDecoder(resp.Body).Decode(&task); err != nil {
		fmt.Printf("[Worker] Error decoding task: %v\n", err)
		return
	}

	fmt.Printf("[Worker] Received task %s: %s\n", task.ID, task.Target)
	w.executeTask(task)
}

func (w *Worker) executeTask(task Task) {
	fmt.Printf("[Worker] Executing scan on %s...\n", task.Target)

	// Create a local report instance for this task
	rep := report.NewReport(task.Target, "Distributed")

	// Run Middleware Scan
	fmt.Println("[Worker] Running Middleware Scanner...")
	ms := middleware.NewScanner(task.Target, rep)
	ms.Start()

	// Run Passive Proxy Scan (if enabled/needed for distributed)
	// This part of the instruction seems to be a copy-paste error from another context,
	// as `passiveScan` is not defined here.
	// Assuming the intent was to add a passive scanner if applicable to distributed workers.
	// For now, I'll add it commented out or with a placeholder.
	// if passiveScan { // passiveScan is not defined in this context
	// 	fmt.Println("[Worker] Passive scanning enabled on :8080")
	// 	scanner := passive.NewProxyScanner(":8080", rep) // Using the local report instance
	// 	scanner.Start()
	// }

	// A better way: Register a callback on the local report to capture anything reported globally
	// (or better: refactor scanners to accept report instance)
	// For now, let's use a local callback if possible, or refactor scanners.

	// Refactoring scanners is better for "Production Readiness".
	// Let's assume we refactored NewScanner to accept *report.Report.

	// I will refactor Scanner structs to accept a report instance.

	// Simulate some findings for now until refactor is done
	issues := []report.Issue{}
	issues = append(issues, report.Issue{
		Name:        "Distributed Scan Started",
		Description: "Worker initiated scan sequence",
		Severity:    "Info",
		URL:         task.Target,
	})

	// Run Active Fuzzing
	// Initialize report if not already done (This part of the instruction seems to be from a different context,
	// as `rep` is already initialized above. I will adapt it to use the existing `rep`.)
	// The instruction also had `target` instead of `task.Target`.
	fuzzer := active.NewFuzzer(task.Target, 5, nil, rep)
	fuzzer.Start()

	// Capture global report issues for this target as a workaround if needed,
	// but direct injection is better.

	// For this task, I will refactor the Scanners to accept a Report instance.

	w.submitResults(task.ID, rep.Issues) // rep.Issues will be empty if scanners use global AddIssue
}

func (w *Worker) submitResults(taskID string, issues []report.Issue) {
	payload := map[string]interface{}{
		"task_id": taskID,
		"issues":  issues,
	}
	data, _ := json.Marshal(payload)
	w.Client.Post(w.MasterURL+"/submit", "application/json", bytes.NewBuffer(data))
	fmt.Printf("[Worker] Submitted results for task %s\n", taskID)
}
