package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The MCPB manifest lists the tools for display; keep it in sync with what the server registers.
func TestMCPBManifestMatchesTools(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "mcpb", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Version string `json:"version"`
		Tools   []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, tool := range m.Tools {
		listed = append(listed, tool.Name)
	}

	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := NewServer(FileSource(filepath.Join(t.TempDir(), "servers.yaml"))).Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var registered []string
	for _, tool := range res.Tools {
		registered = append(registered, tool.Name)
	}
	slices.Sort(listed)
	slices.Sort(registered)
	if !slices.Equal(listed, registered) {
		t.Errorf("mcpb/manifest.json tools %v\ndo not match registered tools %v", listed, registered)
	}

	var plugin struct {
		Version string `json:"version"`
	}
	data, _ = os.ReadFile(filepath.Join("..", "..", "plugin", ".claude-plugin", "plugin.json"))
	if json.Unmarshal(data, &plugin); plugin.Version != m.Version {
		t.Errorf("plugin.json version %q != manifest.json version %q", plugin.Version, m.Version)
	}
}

func TestConfigPathIgnoresUnexpandedTemplate(t *testing.T) {
	t.Setenv("SERVER_CONTROL_CONFIG", "${user_config.servers_file}")
	p, err := ConfigPath()
	if err != nil || p == "${user_config.servers_file}" || filepath.Base(p) != "servers.yaml" {
		t.Errorf("ConfigPath() = %q, %v", p, err)
	}
	t.Setenv("SERVER_CONTROL_CONFIG", "/custom/servers.yaml")
	if p, _ := ConfigPath(); p != "/custom/servers.yaml" {
		t.Errorf("ConfigPath() = %q", p)
	}
}
