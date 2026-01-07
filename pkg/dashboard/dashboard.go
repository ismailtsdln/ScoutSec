package dashboard

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"

	"github.com/ismailtsdln/ScoutSec/pkg/database"
	"github.com/ismailtsdln/ScoutSec/pkg/report"
	"github.com/ismailtsdln/ScoutSec/pkg/scanner/active"
)

type Dashboard struct {
	DB            *database.DB
	clients       map[chan report.Issue]bool
	activeFuzzers map[string]*active.Fuzzer
	mu            sync.Mutex
}

func NewDashboard(db *database.DB) *Dashboard {
	d := &Dashboard{
		DB:            db,
		clients:       make(map[chan report.Issue]bool),
		activeFuzzers: make(map[string]*active.Fuzzer),
	}
	// Register as report listener
	report.RegisterCallback(d.broadcastIssue)
	return d
}

func (d *Dashboard) broadcastIssue(issue report.Issue) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for clientChan := range d.clients {
		select {
		case clientChan <- issue:
		default:
		}
	}
}

func (d *Dashboard) Start(port string) error {
	http.HandleFunc("/", d.indexHandler)
	http.HandleFunc("/stream", d.streamHandler)
	http.HandleFunc("/api/scan/start", d.startScanHandler)
	http.HandleFunc("/api/scan/stop", d.stopScanHandler)

	fmt.Printf("[Dashboard] Server starting on http://localhost:%s\n", port)
	return http.ListenAndServe(":"+port, nil)
}

func (d *Dashboard) streamHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	clientChan := make(chan report.Issue)
	d.mu.Lock()
	d.clients[clientChan] = true
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		delete(d.clients, clientChan)
		d.mu.Unlock()
		close(clientChan)
	}()

	for {
		select {
		case issue := <-clientChan:
			data, _ := json.Marshal(issue)
			fmt.Fprintf(w, "data: %s\n\n", data)
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (d *Dashboard) startScanHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "Target required", http.StatusBadRequest)
		return
	}

	d.mu.Lock()
	if _, exists := d.activeFuzzers[target]; exists {
		d.mu.Unlock()
		http.Error(w, "Scan already in progress for this target", http.StatusConflict)
		return
	}

	// Initialize report if not already done
	report.InitReport(target, "Active")

	fuzzer := active.NewFuzzer(target, 5, nil) // nil client uses default in fuzzer
	d.activeFuzzers[target] = fuzzer
	d.mu.Unlock()

	fmt.Printf("[Dashboard] Starting scan for: %s\n", target)
	go func() {
		fuzzer.Start()
		d.mu.Lock()
		delete(d.activeFuzzers, target)
		d.mu.Unlock()
	}()

	w.WriteHeader(http.StatusOK)
}

func (d *Dashboard) stopScanHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	d.mu.Lock()
	defer d.mu.Unlock()

	if target != "" {
		if fuzzer, exists := d.activeFuzzers[target]; exists {
			fmt.Printf("[Dashboard] Stopping scan for: %s\n", target)
			fuzzer.Cancel()
			delete(d.activeFuzzers, target)
		}
	} else {
		fmt.Println("[Dashboard] Stopping all active scans")
		for t, fuzzer := range d.activeFuzzers {
			fuzzer.Cancel()
			delete(d.activeFuzzers, t)
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (d *Dashboard) indexHandler(w http.ResponseWriter, r *http.Request) {
	findings, err := d.DB.GetAllFindings()
	if err != nil {
		http.Error(w, "Failed to fetch findings", http.StatusInternalServerError)
		return
	}

	// Calculate stats
	stats := map[string]int{
		"Critical": 0,
		"High":     0,
		"Medium":   0,
		"Low":      0,
		"Info":     0,
	}
	for _, f := range findings {
		stats[f.Severity]++
	}
	// Aggregate for the UI box
	stats["LowInfo"] = stats["Low"] + stats["Info"]

	tmpl := template.Must(template.New("dashboard").Parse(indexHTML))
	data := struct {
		Findings []database.Finding
		Stats    map[string]int
	}{
		Findings: findings,
		Stats:    stats,
	}
	tmpl.Execute(w, data)
}

const indexHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ScoutSec v2.0 | Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body { background-color: #0f172a; color: #f8fafc; }
        .card { background-color: #1e293b; border: 1px solid #334155; }
        .severity-Critical { color: #ef4444; }
        .severity-High { color: #f97316; }
        .severity-Medium { color: #eab308; }
        .severity-Low { color: #22c55e; }
        .severity-Info { color: #3b82f6; }
        .live-indicator { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .5; } }
    </style>
</head>
<body class="p-8">
    <div class="max-w-7xl mx-auto">
        <header class="flex justify-between items-center mb-12">
            <div>
                <h1 class="text-4xl font-bold text-blue-500">🛡️ ScoutSec <span class="text-sm font-normal text-slate-500 ml-2">v2.0</span></h1>
                <p class="text-slate-400 mt-2 flex items-center">
                    <span class="w-2 h-2 bg-green-500 rounded-full mr-2 live-indicator"></span>
                    Live Security Monitoring
                </p>
            </div>
            <div class="flex space-x-4">
                <input type="text" id="targetInput" placeholder="Enter target URL..." class="bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                <button onclick="startScan()" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded-lg transition-colors">Start Scan</button>
            </div>
        </header>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-8 mb-12">
            <!-- Stats -->
            <div class="card p-6 rounded-xl flex flex-col items-center justify-center">
                <span id="statCritical" class="text-3xl font-bold text-red-500">{{index .Stats "Critical"}}</span>
                <span class="text-slate-500 uppercase text-xs mt-2">Critical</span>
            </div>
            <div class="card p-6 rounded-xl flex flex-col items-center justify-center">
                <span id="statHigh" class="text-3xl font-bold text-orange-500">{{index .Stats "High"}}</span>
                <span class="text-slate-500 uppercase text-xs mt-2">High</span>
            </div>
            <div class="card p-6 rounded-xl flex flex-col items-center justify-center">
                <span id="statMedium" class="text-3xl font-bold text-yellow-500">{{index .Stats "Medium"}}</span>
                <span class="text-slate-500 uppercase text-xs mt-2">Medium</span>
            </div>
            <div class="card p-6 rounded-xl flex flex-col items-center justify-center">
                <span id="statLow" class="text-3xl font-bold text-green-500">{{index .Stats "LowInfo"}}</span>
                <span class="text-slate-500 uppercase text-xs mt-2">Low/Info</span>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
            <div class="card p-6 rounded-xl md:col-span-2">
                <h2 class="text-xl font-semibold mb-6 flex justify-between items-center">
                   <span>Real-time Finding Feed</span>
                   <span class="text-xs font-normal text-slate-400">Updates automatically</span>
                </h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left" id="findingsTable">
                        <thead>
                            <tr class="text-slate-500 text-sm border-b border-slate-700">
                                <th class="pb-3 text-sm">Vulnerability</th>
                                <th class="pb-3 text-center text-sm">Severity</th>
                                <th class="pb-3 text-sm">Target</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .Findings}}
                            <tr class="border-b border-slate-800 hover:bg-slate-700/50 transition-colors">
                                <td class="py-4 font-medium">{{.Name}}</td>
                                <td class="py-4 text-center">
                                    <span class="px-2 py-1 rounded-md text-xs font-bold severity-{{.Severity}} bg-slate-800 border border-slate-700">
                                        {{.Severity}}
                                    </span>
                                </td>
                                <td class="py-4 text-sm text-slate-400 truncate max-w-xs">{{.URL}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card p-6 rounded-xl">
                <h2 class="text-xl font-semibold mb-6">Severity Distribution</h2>
                <div class="relative h-64">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
        </div>
    </div>

    <script>
        const stats = {
            'Critical': {{index .Stats "Critical"}},
            'High': {{index .Stats "High"}},
            'Medium': {{index .Stats "Medium"}},
            'Low': {{index .Stats "Low"}},
            'Info': {{index .Stats "Info"}}
        };

        const ctx = document.getElementById('severityChart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [stats.Critical, stats.High, stats.Medium, stats.Low, stats.Info],
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6'],
                    borderWidth: 0
                }]
            },
            options: { cutout: '70%', responsive: true, maintainAspectRatio: false }
        });

        const eventSource = new EventSource("/stream");
        eventSource.onmessage = function(event) {
            const issue = JSON.parse(event.data);
            addFindingToTable(issue);
            updateStats(issue.severity);
        };

        function addFindingToTable(issue) {
            const table = document.getElementById('findingsTable').getElementsByTagName('tbody')[0];
            const row = table.insertRow(0);
            row.className = "border-b border-slate-800 bg-blue-500/10 transition-all duration-1000";
            row.innerHTML = 
                '<td class="py-4 font-medium">' + issue.name + '</td>' +
                '<td class="py-4 text-center">' +
                '    <span class="px-2 py-1 rounded-md text-xs font-bold severity-' + issue.severity + ' bg-slate-800 border border-slate-700">' +
                '        ' + issue.severity +
                '    </span>' +
                '</td>' +
                '<td class="py-4 text-sm text-slate-400 truncate max-w-xs">' + issue.url + '</td>';
            setTimeout(function() { row.classList.remove('bg-blue-500/10'); }, 2000);
        }

        function updateStats(severity) {
            stats[severity]++;
            const statId = severity === 'Info' || severity === 'Low' ? 'statLow' : 'stat' + severity;
            const el = document.getElementById(statId);
            if (el) el.innerText = parseInt(el.innerText) + 1;
            
            chart.data.datasets[0].data = [stats.Critical, stats.High, stats.Medium, stats.Low, stats.Info];
            chart.update();
        }

        function startScan() {
            const target = document.getElementById('targetInput').value;
            fetch('/api/scan/start?target=' + encodeURIComponent(target))
                .then(() => alert('Scan started for ' + target));
        }
    </script>
</body>
</html>
`
