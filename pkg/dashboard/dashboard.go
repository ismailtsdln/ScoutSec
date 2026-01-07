package dashboard

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/ismailtsdln/ScoutSec/pkg/database"
)

type Dashboard struct {
	DB *database.DB
}

func NewDashboard(db *database.DB) *Dashboard {
	return &Dashboard{DB: db}
}

func (d *Dashboard) Start(port string) error {
	http.HandleFunc("/", d.indexHandler)
	fmt.Printf("[Dashboard] Server starting on http://localhost:%s\n", port)
	return http.ListenAndServe(":"+port, nil)
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
    <title>ScoutSec Dashboard</title>
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
    </style>
</head>
<body class="p-8">
    <div class="max-w-7xl mx-auto">
        <header class="flex justify-between items-center mb-12">
            <div>
                <h1 class="text-4xl font-bold text-blue-500">🛡️ ScoutSec</h1>
                <p class="text-slate-400 mt-2">Security Scanning Dashboard</p>
            </div>
            <div class="flex space-x-4">
                <div class="card p-4 rounded-lg flex items-center space-x-3">
                    <i class="fas fa-shield-alt text-2xl text-blue-400"></i>
                    <div>
                        <span class="block text-2xl font-bold">{{len .Findings}}</span>
                        <span class="text-xs text-slate-400 uppercase">Total Findings</span>
                    </div>
                </div>
            </div>
        </header>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
            <div class="card p-6 rounded-xl md:col-span-2">
                <h2 class="text-xl font-semibold mb-6">Recent Findings</h2>
                <div class="overflow-x-auto">
                    <table class="w-full text-left">
                        <thead>
                            <tr class="text-slate-500 text-sm border-b border-slate-700">
                                <th class="pb-3">Vulnerability</th>
                                <th class="pb-3 text-center">Severity</th>
                                <th class="pb-3">Target</th>
                                <th class="pb-3 text-right">Date</th>
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
                                <td class="py-4 text-right text-xs text-slate-500">{{.CreatedAt.Format "Jan 02, 15:04"}}</td>
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
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [
                        {{index .Stats "Critical"}},
                        {{index .Stats "High"}},
                        {{index .Stats "Medium"}},
                        {{index .Stats "Low"}},
                        {{index .Stats "Info"}}
                    ],
                    backgroundColor: [
                        '#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6'
                    ],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', padding: 20 }
                    }
                },
                cutout: '70%',
                responsive: true,
                maintainAspectRatio: false
            }
        });
    </script>
</body>
</html>
`
