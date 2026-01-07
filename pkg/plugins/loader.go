package plugins

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/ismailtsdln/ScoutSec/pkg/report"
)

// ScoutPlugin is the interface that custom plugins must implement.
type ScoutPlugin interface {
	Name() string
	Run(target string) ([]report.Issue, error)
}

// LoadPlugins loads all .so plugins from the specified directory.
func LoadPlugins(dir string) ([]ScoutPlugin, error) {
	var plugins []ScoutPlugin

	// Check if dir exists
	// Walk directory
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".so") {
			fmt.Printf("Loading plugin: %s\n", path)
			p, err := plugin.Open(path)
			if err != nil {
				return fmt.Errorf("failed to open plugin %s: %v", path, err)
			}

			// Look for "Plugin" symbol
			symPlugin, err := p.Lookup("Plugin")
			if err != nil {
				return fmt.Errorf("plugin %s does not export 'Plugin' symbol: %v", path, err)
			}

			// Assert interface
			scoutPlugin, ok := symPlugin.(ScoutPlugin)
			if !ok {
				return fmt.Errorf("plugin %s 'Plugin' symbol does not implement ScoutPlugin interface", path)
			}

			plugins = append(plugins, scoutPlugin)
		}
		return nil
	})

	return plugins, err
}
