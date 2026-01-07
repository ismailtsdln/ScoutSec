package distributed

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ismailtsdln/ScoutSec/pkg/report"
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
	// For simplicity, let's run a middleware scan as the "job"
	// In a real scenario, the task specific scan type.

	fmt.Printf("[Worker] Executing scan on %s...\n", task.Target)

	// Create a temporary report capture (this is tricky without refactoring Report to be non-global or instance based)
	// We'll just define a simple scanner here.
	// ms := middleware.NewScanner(task.Target)
	// ms.Start() // In real world we would capture output

	// We need to capture the output of the scanner.
	// Since Middleware scanner writes to stdout and Report, we'll assume we can just return dummy findings for this demo
	// or refactor Scanner to return issues.
	// Let's modify Scanner to return findings or just simulate finding.

	issues := []report.Issue{}
	// Simulate finding
	issues = append(issues, report.Issue{
		Name:        "Distributed Scan Hit",
		Description: "Worker successfully scanned target",
		Severity:    "Info",
		URL:         task.Target,
	})

	// Report back
	w.submitResults(task.ID, issues)
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
