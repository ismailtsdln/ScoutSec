package plugins

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/ismailtsdln/ScoutSec/pkg/report"
	lua "github.com/yuin/gopher-lua"
)

// LuaPlugin represents a scanning check written in Lua.
type LuaPlugin struct {
	Path string
	L    *lua.LState
}

// NewLuaPlugin creates a new instance of LuaPlugin.
func NewLuaPlugin(path string) *LuaPlugin {
	return &LuaPlugin{
		Path: path,
		L:    lua.NewState(),
	}
}

// Close closes the Lua state.
func (p *LuaPlugin) Close() {
	p.L.Close()
}

// Run executes the Lua script with the given target.
func (p *LuaPlugin) Run(target string) error {
	// Register the "report_finding" function in Lua
	p.L.SetGlobal("report_finding", p.L.NewFunction(func(L *lua.LState) int {
		name := L.CheckString(1)
		desc := L.CheckString(2)
		sev := L.CheckString(3)
		evidence := L.CheckString(4)

		report.AddIssue(report.Issue{
			Name:        name,
			Description: desc,
			Severity:    sev,
			URL:         target,
			Evidence:    evidence,
		})
		return 0
	}))

	// Set target variable in Lua
	p.L.SetGlobal("target", lua.LString(target))

	// Run the script
	if err := p.L.DoFile(p.Path); err != nil {
		return fmt.Errorf("error running lua plugin %s: %v", p.Path, err)
	}

	return nil
}

// LoadLuaPlugins discovers and loads all .lua files in a directory.
func LoadLuaPlugins(dir string) ([]*LuaPlugin, error) {
	var plugins []*LuaPlugin

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".lua") {
			plugins = append(plugins, NewLuaPlugin(path))
		}
		return nil
	})

	return plugins, err
}
