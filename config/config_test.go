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
