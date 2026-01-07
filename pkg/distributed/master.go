package distributed

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ismailtsdln/ScoutSec/pkg/report"
)

// Task represents a scanning job.
type Task struct {
	ID       string `json:"id"`
	Target   string `json:"target"`
	Status   string `json:"status"` // Pending, Running, Completed, Failed
	WorkerID string `json:"worker_id,omitempty"`
}

// Master manages tasks and workers.
type Master struct {
	Tasks      map[string]*Task
	TasksLock  sync.RWMutex
	Findings   []report.Issue
	ServerPort string
}

// NewMaster creates a new Master node.
func NewMaster(port string) *Master {
	return &Master{
		Tasks:      make(map[string]*Task),
		ServerPort: port,
	}
}

// AddTask adds a new task to the queue.
func (m *Master) AddTask(target string) string {
	m.TasksLock.Lock()
	defer m.TasksLock.Unlock()

	id := fmt.Sprintf("task-%d", time.Now().UnixNano())
	m.Tasks[id] = &Task{
		ID:     id,
		Target: target,
		Status: "Pending",
	}
	fmt.Printf("[Master] Added task %s for target %s\n", id, target)
	return id
}

// GetTaskHandler distributes tasks to workers.
func (m *Master) GetTaskHandler(w http.ResponseWriter, r *http.Request) {
	m.TasksLock.Lock()
	defer m.TasksLock.Unlock()

	for _, task := range m.Tasks {
		if task.Status == "Pending" {
			task.Status = "Running"
			task.WorkerID = r.RemoteAddr // Simple identification
			json.NewEncoder(w).Encode(task)
			fmt.Printf("[Master] Assigned task %s to worker %s\n", task.ID, task.WorkerID)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// SubmitResultsHandler receives findings from workers.
func (m *Master) SubmitResultsHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TaskID string         `json:"task_id"`
		Issues []report.Issue `json:"issues"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	m.TasksLock.Lock()
	defer m.TasksLock.Unlock()

	if task, ok := m.Tasks[body.TaskID]; ok {
		task.Status = "Completed"
		m.Findings = append(m.Findings, body.Issues...)
		for _, issue := range body.Issues {
			report.AddIssue(issue)
		}
		fmt.Printf("[Master] Received %d findings for task %s\n", len(body.Issues), body.TaskID)
	} else {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Start starts the Master HTTP server.
func (m *Master) Start() error {
	http.HandleFunc("/task", m.GetTaskHandler)
	http.HandleFunc("/submit", m.SubmitResultsHandler)

	fmt.Printf("[Master] Listening on port %s\n", m.ServerPort)
	return http.ListenAndServe(":"+m.ServerPort, nil)
}
