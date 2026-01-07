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

	fmt.Printf("[Worker] Received task %s: %s (%s)\n", task.ID, task.Target, task.ScanType)
	w.executeTask(task)
}

func (w *Worker) executeTask(task Task) {
	fmt.Printf("[Worker] Executing %s scan on %s...\n", task.ScanType, task.Target)

	// Create a local report instance for this task
	rep := report.NewReport(task.Target, "Distributed-"+task.ScanType)

	switch task.ScanType {
	case "middleware":
		fmt.Println("[Worker] Running Middleware Scanner...")
		ms := middleware.NewScanner(task.Target, rep)
		ms.Start()
	case "active":
		fmt.Println("[Worker] Running Active Fuzzer...")
		fuzzer := active.NewFuzzer(task.Target, 5, nil, rep)
		fuzzer.Start()
	default:
		fmt.Printf("[Worker] Unknown scan type: %s\n", task.ScanType)
		// Simülasyon için dummy findings eklenebilir
		rep.AddIssue(report.Issue{
			Name:        "Unknown Scan Type",
			Description: fmt.Sprintf("Worker received a task with unknown type: %s", task.ScanType),
			Severity:    "Info",
			URL:         task.Target,
		})
	}

	// Report back
	w.submitResults(task.ID, rep.Issues)
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
