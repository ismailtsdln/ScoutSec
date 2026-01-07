package utils

import (
	"fmt"
	"strings"
)

// ProgressBar displays a simple CLI progress bar.
type ProgressBar struct {
	Total   int
	Current int
	Width   int
}

// NewProgressBar creates a new progress bar.
func NewProgressBar(total int) *ProgressBar {
	return &ProgressBar{
		Total: total,
		Width: 50,
	}
}

// Update increments the progress and displays the bar.
func (pb *ProgressBar) Update() {
	pb.Current++
	pb.Render()
}

// Render displays the current progress.
func (pb *ProgressBar) Render() {
	percent := float64(pb.Current) / float64(pb.Total) * 100
	filled := int(float64(pb.Width) * float64(pb.Current) / float64(pb.Total))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", pb.Width-filled)
	fmt.Printf("\r[%s] %.1f%% (%d/%d)", bar, percent, pb.Current, pb.Total)

	if pb.Current >= pb.Total {
		fmt.Println()
	}
}

// Complete marks the progress as 100%.
func (pb *ProgressBar) Complete() {
	pb.Current = pb.Total
	pb.Render()
}
