package config

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestParseCommand(t *testing.T) {
	args := []string{
		"-I",
		".",
		"-v",
		"foo",
	}
	c := parseCommands(args)

	if diff := cmp.Diff(c, Commands{"foo"}); diff != "" {
		t.Errorf("Unmatched parsed commands, diff=%s", diff)
	}
}

func TestParseCommandSkipsOptionValues(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "request before command", args: []string{"--request", "request.json", "test", "main.vcl"}},
		{name: "request after command", args: []string{"test", "--request", "request.json", "main.vcl"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(Commands{"test", "main.vcl"}, parseCommands(tt.args)); diff != "" {
				t.Errorf("Unmatched parsed commands, diff=%s", diff)
			}
		})
	}
}

func TestConfigRequestFile(t *testing.T) {
	t.Run("loads request override", func(t *testing.T) {
		path := t.TempDir() + "/request.json"
		if err := os.WriteFile(path, []byte(`{"path": "/foo", "headers": {"X-Test": "1"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := New([]string{"--request", path, "test", "main.vcl"})
		if err != nil {
			t.Fatalf("Failed to initialize config: %s", err)
		}
		if c.Testing.OverrideRequest == nil || c.Testing.OverrideRequest.Path != "/foo" {
			t.Errorf("Request override is not loaded: %+v", c.Testing.OverrideRequest)
		}
		if diff := cmp.Diff(Commands{"test", "main.vcl"}, c.Commands); diff != "" {
			t.Errorf("Unmatched parsed commands, diff=%s", diff)
		}
	})

	t.Run("returns error for missing request file", func(t *testing.T) {
		if _, err := New([]string{"--request", t.TempDir() + "/missing.json", "test"}); err == nil {
			t.Error("Expected an error for a missing request file")
		}
	})
}

func TestConfigFromCLI(t *testing.T) {
	args := []string{
		"-I",
		".",
		"-h",
		"-v",
		"-vv",
		"-r",
		"-V",
		"--json",
		"-t",
		"foo",
		"-t",
		"bar",
		"lint",
	}
	c, err := New(args)
	if err != nil {
		t.Errorf("Failed to initialize config: %s", err)
		return
	}

	expect := &Config{
		IncludePaths: []string{"."},
		Help:         true,

		Version:  true,
		Remote:   true,
		Json:     true,
		Commands: Commands{"lint"},
		Linter: &LinterConfig{
			VerboseLevel:      "",
			VerboseWarning:    true,
			VerboseInfo:       true,
			IgnoreSubroutines: []string{"vcl_pipe"},
		},
		Simulator: &SimulatorConfig{
			Port:            3124,
			IncludePaths:    []string{"."},
			OverrideRequest: &RequestConfig{},
		},
		Testing: &TestConfig{
			Filter:          "*.test.vcl",
			IncludePaths:    []string{"."},
			Tags:            []string{"foo", "bar"},
			OverrideRequest: &RequestConfig{},
		},
		Console: &ConsoleConfig{
			Scope:           "recv",
			OverrideRequest: &RequestConfig{},
		},
		Format: &FormatConfig{
			IndentWidth:                2,
			TrailingCommentWidth:       1,
			LineWidth:                  120,
			IndentStyle:                "space",
			ExplicitStringConcat:       true,
			SortDeclarationProperty:    false,
			AlignDeclarationProperty:   false,
			ElseIf:                     false,
			ReturnStatementParenthesis: true,
			SortDeclaration:            false,
			AlignTrailingComment:       false,
			CommentStyle:               "none",
			ShouldUseUnset:             false,
			BreakCompoundConditions:    true,
		},
		OverrideBackends: make(map[string]*OverrideBackend),
	}

	if diff := cmp.Diff(c, expect, cmpopts.IgnoreFields(Config{}, "FastlyServiceID", "FastlyApiKey")); diff != "" {
		t.Errorf("Unmatched Config struct, diff=%s", diff)
	}
}

func TestConfigFromEnv(t *testing.T) {
	os.Setenv("FASTLY_SERVICE_ID", "example_service_id")
	os.Setenv("FASTLY_API_KEY", "example_api_key")

	c, err := New([]string{})
	if err != nil {
		t.Errorf("Failed to initialize config: %s", err)
	}
	if c.FastlyServiceID != "example_service_id" {
		t.Errorf("Unmatched FastlyServiceID field, expect=%s, got=%s", "example_service_id", c.FastlyServiceID)
	}
	if c.FastlyApiKey != "example_api_key" {
		t.Errorf("Unmatched FastlyApiKey field, expect=%s, got=%s", "example_api_key", c.FastlyApiKey)
	}
}

// TestFindConfigFileAscendsToRoot verifies the platform-agnostic ascent
// termination (parent == cwd): from a temp dir with no config above it,
// findConfigFile must ascend to the root, stop, and return ("", nil) — not hang.
func TestFindConfigFileAscendsToRoot(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	got, err := findConfigFile()
	if err != nil {
		t.Fatalf("findConfigFile error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected no config file found, got %q", got)
	}
}
