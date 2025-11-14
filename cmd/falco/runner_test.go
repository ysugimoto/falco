package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/linter"
	"github.com/ysugimoto/falco/resolver"
	"github.com/ysugimoto/falco/terraform"
)

type RepoExampleTestMetadata struct {
	name     string
	fileName string
	errors   int
	warnings int
	infos    int
	runError bool
}

func loadRepoExampleTestMetadata() []RepoExampleTestMetadata {
	ret := []RepoExampleTestMetadata{
		{
			name:     "example 1",
			fileName: "../../examples/linter/default01.vcl",
			errors:   0,
			warnings: 0,
			infos:    0,
		},
		{
			name:     "example 2",
			fileName: "../../examples/linter/default02.vcl",
			errors:   1,
			warnings: 0,
			infos:    0,
			runError: true,
		},
		{
			name:     "example 3",
			fileName: "../../examples/linter/default03.vcl",
			errors:   0,
			warnings: 0,
			infos:    2,
		},
		{
			name:     "example 4",
			fileName: "../../examples/linter/default04.vcl",
			errors:   0,
			warnings: 0,
			infos:    1,
		},
		{
			name:     "undocumented",
			fileName: "../../examples/linter/undocumented.vcl",
			errors:   0,
			warnings: 0,
			infos:    0,
		},
	}

	// Run custom linter testing only in CI env
	if v := os.Getenv("CI"); v != "" {
		ret = append(ret, RepoExampleTestMetadata{
			name:     "run custom linter",
			fileName: "../../examples/linter/custom_linter.vcl",
			errors:   0,
			warnings: 0,
			infos:    0,
		})
	}

	return ret
}

func loadFromTfJson(fileName string, t *testing.T) ([]resolver.Resolver, *terraform.TerraformFetcher) {
	buf, err := os.ReadFile(fileName)
	if err != nil {
		t.Fatalf("Unexpected error %s reading file %s ", fileName, err)
	}

	services, err := terraform.UnmarshalTerraformPlannedInput(buf)
	if err != nil {
		t.Fatalf("Unexpected error %s unarshalling %s ", fileName, err)
	}

	rslv := resolver.NewTerraformResolver(services)
	f := terraform.NewTerraformFetcher(services)
	return rslv, f
}

func TestResolveExternalWithExternalProperties(t *testing.T) {
	for _, fileName := range []string{"../../terraform/data/terraform-valid.json", "../../terraform/data/terraform-valid-weird-name.json"} {
		rslv, f := loadFromTfJson(fileName, t)
		c := &config.Config{
			Linter: &config.LinterConfig{
				VerboseWarning: true,
			},
		}
		ret, err := NewRunner(c, f).Run(rslv[0])
		if err != nil {
			t.Fatalf("Unexpected Run() error: %s", err)
		}
		if ret.Infos > 0 {
			t.Errorf("Infos expects 0, got %d", ret.Infos)
		}
		if ret.Warnings != 0 {
			t.Errorf("Warning expects 0, got %d", ret.Warnings)
		}
		if ret.Errors > 0 {
			t.Errorf("Errors expects 0, got %d", ret.Errors)
		}
	}
}

func TestResolveExternalWithNoExternalProperties(t *testing.T) {
	fileName := "../../terraform/data/terraform-empty.json"
	rslv, f := loadFromTfJson(fileName, t)
	c := &config.Config{
		Linter: &config.LinterConfig{
			VerboseWarning: true,
		},
	}
	ret, err := NewRunner(c, f).Run(rslv[0])
	if err != nil {
		t.Fatalf("Unexpected Run() error: %s", err)
	}
	if ret.Infos > 0 {
		t.Errorf("Infos expects 0, got %d", ret.Infos)
	}
	if ret.Warnings != 0 {
		t.Errorf("Warning expects 0, got %d", ret.Warnings)
	}
	if ret.Errors > 0 {
		t.Errorf("Errors expects 0, got %d", ret.Errors)
	}
}

func TestResolveWithDuplicateDeclarations(t *testing.T) {
	fileName := "../../terraform/data/terraform-duplicate.json"
	rslv, f := loadFromTfJson(fileName, t)
	c := &config.Config{
		Linter: &config.LinterConfig{
			VerboseWarning: true,
		},
	}
	ret, err := NewRunner(c, f).Run(rslv[0])
	if err != nil {
		t.Fatalf("Unexpected Run() error: %s", err)
	}

	if ret.Errors != 1 {
		t.Errorf("Errors expects 1, got %d", ret.Errors)
	}
}

func TestResolveModulesWithVCLExtension(t *testing.T) {
	fileName := "../../terraform/data/terraform-modules-extension.json"
	rslv, f := loadFromTfJson(fileName, t)
	c := &config.Config{
		Linter: &config.LinterConfig{
			VerboseWarning: true,
		},
	}

	ret, err := NewRunner(c, f).Run(rslv[0])
	if err != nil {
		t.Fatalf("Unexpected Run() error: %s", err)
	}

	if ret.Errors > 0 {
		t.Errorf("Errors expects 0, got %d", ret.Errors)
	}
}

func TestResolveModulesWithoutVCLExtension(t *testing.T) {
	fileName := "../../terraform/data/terraform-modules-without-extension.json"
	rslv, f := loadFromTfJson(fileName, t)
	c := &config.Config{
		Linter: &config.LinterConfig{
			VerboseWarning: true,
		},
	}

	ret, err := NewRunner(c, f).Run(rslv[0])
	if err != nil {
		t.Fatalf("Unexpected Run() error: %s", err)
	}

	if ret.Errors > 0 {
		t.Errorf("Errors expects 0, got %d", ret.Errors)
	}
}

func TestTesterWithTerraform(t *testing.T) {
	fileName := "../../terraform/data/terraform-valid.json"
	rslv, f := loadFromTfJson(fileName, t)
	c := &config.Config{
		Linter: &config.LinterConfig{
			VerboseWarning: true,
		},
		Testing: &config.TestConfig{
			IncludePaths: []string{"../../terraform/testing/"},
			Filter:       "*.test.vcl",
		},
	}

	res, err := NewRunner(c, f).Test(rslv[0])
	if err != nil {
		t.Fatalf("Unexpected Run() error: %s", err)
	}
	if res.Statistics.Fails > 0 || res.Statistics.Passes != 1 {
		t.Errorf("Expected 0 failures and 1 pass, got %d failures and %d passes", res.Statistics.Fails, res.Statistics.Passes)
	}
}

// Tests for all the example code in the repo to make sure we don't accidentally
// break those as they are the first thing someone might try on the repo.

// Test cases for when the command runs in stdout mode (no -json flag set)
func TestRepositoryExamples(t *testing.T) {
	tests := loadRepoExampleTestMetadata()
	c := &config.Config{
		Linter: &config.LinterConfig{
			VerboseWarning:    true,
			IgnoreSubroutines: []string{"vcl_pipe"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolvers, err := resolver.NewFileResolvers(tt.fileName, c.IncludePaths)
			if err != nil {
				t.Errorf("Unexpected resolver creation error: %s", err)
				return
			}

			ret, err := NewRunner(c, nil).Run(resolvers[0])
			if err != nil {
				if !tt.runError {
					t.Errorf("Unexpected runner error: %s", err)
				}
				return
			}

			if ret.Infos != tt.infos {
				t.Errorf("Infos expects %d, got %d", tt.infos, ret.Infos)
			}
			if ret.Warnings != tt.warnings {
				t.Errorf("Warning expects %d, got %d", tt.warnings, ret.Warnings)
			}
			if ret.Errors != tt.errors {
				t.Errorf("Errors expects %d, got %d", tt.errors, ret.Errors)
			}
		})
	}
}

// Test cases for JSON mode (-json flag set)
func TestRepositoryExamplesJSONMode(t *testing.T) {
	tests := loadRepoExampleTestMetadata()
	c := &config.Config{
		Json: true,
		Linter: &config.LinterConfig{
			VerboseWarning:    true,
			IgnoreSubroutines: []string{"vcl_pipe"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolvers, err := resolver.NewFileResolvers(tt.fileName, c.IncludePaths)
			if err != nil {
				t.Errorf("Unexpected runner creation error: %s", err)
				return
			}
			ret, err := NewRunner(c, nil).Run(resolvers[0])
			if tt.errors != 0 {
				if err != nil {
					t.Errorf("Unexpected error running Run(): %s", err)
				}
				return
			}
			if ret.Infos != tt.infos {
				t.Errorf("Infos expects %d, got %d", tt.infos, ret.Infos)
			}
			if ret.Warnings != tt.warnings {
				t.Errorf("Warning expects %d, got %d", tt.warnings, ret.Warnings)
			}
			if ret.Errors != tt.errors {
				t.Errorf("Errors expects %d, got %d", tt.errors, ret.Errors)
			}
			var c int
			for _, v := range ret.LintErrors {
				c += len(v)
			}
			if c != tt.infos+tt.warnings+tt.errors {
				t.Errorf("Expected %d linting errors, got %d", tt.infos+tt.warnings+tt.errors, c)
			}

			countLintErrorsWithSeverity := func(sev linter.Severity) int {
				var counter int = 0
				for result := range ret.LintErrors {
					for _, issue := range ret.LintErrors[result] {
						if issue.Severity == sev {
							counter++
						}
					}
				}
				return counter
			}
			testIssuesWithSeverity := func(sev linter.Severity, expected int) {
				var issueCount = countLintErrorsWithSeverity(sev)
				if issueCount != expected {
					t.Errorf("Expected %d linting errors with severity %s, got %d", expected, sev, issueCount)
				}
			}
			testIssuesWithSeverity("Info", tt.infos)
			testIssuesWithSeverity("Warning", tt.warnings)
			testIssuesWithSeverity("Error", tt.errors)
		})
	}
}

func TestTester(t *testing.T) {
	tests := []struct {
		name   string
		main   string
		filter string
		passes int
	}{
		{
			name:   "table manipulation test",
			main:   "../../examples/testing/table_manipulation/table_manipulation.vcl",
			filter: "*table_*.test.vcl",
			passes: 2,
		},
		{
			name:   "empty and notset value test",
			main:   "../../examples/testing/default_values/default_values.vcl",
			filter: "*values.test.vcl",
			passes: 16,
		},
		{
			name:   "assertions test",
			main:   "../../examples/testing/assertion/assertion.vcl",
			filter: "*assertion.test.vcl",
			passes: 5,
		},
		{
			name:   "grouping test",
			main:   "../../examples/testing/group/group.vcl",
			filter: "*group.test.vcl",
			passes: 3,
		},
		{
			name:   "mockging test",
			main:   "../../examples/testing/mock_subroutine/mock_subroutine.vcl",
			filter: "*mock_subroutine.test.vcl",
			passes: 6,
		},
		{
			name:   "overriding variables test",
			main:   "../../examples/testing/override_variables/override_variables.vcl",
			filter: "*override_variables.test.vcl",
			passes: 6,
		},
		{
			name:   "base64 functional test",
			main:   "../../examples/testing/base64/main.vcl",
			filter: "*base64.test.vcl",
			passes: 12,
		},
		{
			name:   "regex grouped variables test",
			main:   "../../examples/testing/regex/regex.vcl",
			filter: "*regex.test.vcl",
			passes: 72,
		},
		{
			name:   "header subfield dealing test",
			main:   "../../examples/testing/subfield-header-dealing/default.vcl",
			filter: "*default.test.vcl",
			passes: 10,
		},
		{
			name:   "synthetic vs obj.response",
			main:   "../../examples/testing/synthetic_response/default.vcl",
			filter: "*default.test.vcl",
			passes: 2,
		},
		{
			name:   "rate limiting",
			main:   "../../examples/testing/rate_limiting/main.vcl",
			filter: "*main.test.vcl",
			passes: 1,
		},
		{
			name:   "origin host header",
			main:   "../../examples/testing/origin_host_header/main.vcl",
			filter: "*main.test.vcl",
			passes: 5,
		},
		{
			name:   "do not omit query sign",
			main:   "../../examples/testing/query_sign/default.vcl",
			filter: "*default.test.vcl",
			passes: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			main, err := filepath.Abs(tt.main)
			if err != nil {
				t.Errorf("Unexpected making absolute path error: %s", err)
				return
			}
			c := &config.Config{
				Linter: &config.LinterConfig{
					VerboseWarning: true,
				},
				Testing: &config.TestConfig{
					Filter: tt.filter,
					YamlOverrideVariables: map[string]any{
						"tls.client.certificate.is_cert_missing": true,
						"client.geo.area_code":                   100,
						"req.digest.ratio":                       0.8,
						"client.as.name":                         "Foobar",
					},
					CLIOverrideVariables: []string{
						"client.geo.area_code=200", // will be overridden
					},
				},
				Commands: config.Commands{"test", main},
			}
			resolvers, err := resolver.NewFileResolvers(tt.main, c.IncludePaths)
			if err != nil {
				t.Errorf("Unexpected runner creation error: %s", err)
				return
			}
			ret, err := NewRunner(c, nil).Test(resolvers[0])
			if err != nil {
				t.Errorf("Unexpected runner creation error: %s", err)
				return
			}
			for _, v := range ret.Results {
				for _, c := range v.Cases {
					if c.Error != nil {
						t.Errorf(`Test case "%s" raises error: %s`, c.Name, c.Error)
						return
					}
				}
			}
			if ret.Statistics.Fails > 0 {
				t.Errorf("Testing fails should be zero, got: %d", ret.Statistics.Fails)
				return
			}
			if ret.Statistics.Passes != tt.passes {
				t.Errorf("Testing passes should be %d, got: %d", tt.passes, ret.Statistics.Passes)
				return
			}
		})
	}
}

func TestFastlyGeneratedVCLLinting(t *testing.T) {
	c, err := config.New([]string{"--generated"})
	if err != nil {
		t.Errorf("Unexpected config pointer generation error: %s", err)
		return
	}

	resolvers, err := resolver.NewFileResolvers("../../examples/linter/fastly_generated.vcl", c.IncludePaths)
	if err != nil {
		t.Errorf("Unexpected runner creation error: %s", err)
		return
	}
	ret, err := NewRunner(c, nil).Run(resolvers[0])
	if err != nil {
		t.Errorf("Unexpected linting error: %s", err)
		return
	}
	if ret.Infos != 2 {
		t.Errorf("Infos expects 2, got %d", ret.Infos)
	}
	if ret.Warnings != 3 {
		t.Errorf("Warning expects 3, got %d", ret.Warnings)
	}
	if ret.Errors > 0 {
		t.Errorf("Errors expects 0, got %d", ret.Errors)
	}
}

func TestInjectDictionaryTesting(t *testing.T) {
	tests := []struct {
		name    string
		main    string
		inject  bool
		passes  int
		isError bool
	}{
		{
			name:   "inject dictionary",
			main:   "../../examples/testing/inject_dictionary/inject_dictionary.vcl",
			inject: true,
			passes: 1,
		},
		{
			name:    "inject dictionary",
			main:    "../../examples/testing/inject_dictionary/inject_dictionary.vcl",
			passes:  0,
			isError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			main, err := filepath.Abs(tt.main)
			if err != nil {
				t.Errorf("Unexpected making absolute path error: %s", err)
				return
			}
			c := &config.Config{
				Linter: &config.LinterConfig{
					VerboseWarning: true,
				},
				Testing: &config.TestConfig{
					Filter: "*.test.vcl",
				},
				Commands: config.Commands{"test", main},
			}
			if tt.inject {
				c.Testing.OverrideEdgeDictionaries = map[string]config.EdgeDictionary{
					"injected_dictionary": map[string]string{
						"is_maintenance": "1",
					},
				}
			}
			resolvers, err := resolver.NewFileResolvers(main, c.IncludePaths)
			if err != nil {
				t.Errorf("Unexpected runner creation error: %s", err)
				return
			}
			ret, err := NewRunner(c, nil).Test(resolvers[0])
			if err != nil {
				t.Errorf("Unexpected runner creation error: %s", err)
			}
			for _, v := range ret.Results {
				for _, c := range v.Cases {
					if c.Error != nil {
						if !tt.isError {
							t.Errorf(`Test case "%s" raises error: %s`, c.Name, c.Error)
						}
						return
					}
				}
			}
			if ret.Statistics.Passes != tt.passes {
				t.Errorf("Testing passes should be %d, got: %d", tt.passes, ret.Statistics.Passes)
				return
			}
		})
	}
}

func TestSkippingTests(t *testing.T) {
	tests := []struct {
		name    string
		main    string
		tags    []string
		skipped int
	}{
		{
			name:    "no tags are provided",
			main:    "../../examples/testing/skipping_tests/default.vcl",
			tags:    []string{},
			skipped: 2,
		},
		{
			name:    "provide prod tag",
			main:    "../../examples/testing/skipping_tests/default.vcl",
			tags:    []string{"prod"},
			skipped: 2,
		},
		{
			name:    "provide dev tag",
			main:    "../../examples/testing/skipping_tests/default.vcl",
			tags:    []string{"dev"},
			skipped: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			main, err := filepath.Abs(tt.main)
			if err != nil {
				t.Errorf("Unexpected making absolute path error: %s", err)
				return
			}
			c := &config.Config{
				Linter: &config.LinterConfig{
					VerboseWarning: true,
				},
				Testing: &config.TestConfig{
					Filter: "*/skipping_tests/*.test.vcl",
					Tags:   tt.tags,
				},
				Commands: config.Commands{"test", main},
			}
			resolvers, err := resolver.NewFileResolvers(main, c.IncludePaths)
			if err != nil {
				t.Errorf("Unexpected runner creation error: %s", err)
				return
			}
			ret, err := NewRunner(c, nil).Test(resolvers[0])
			if err != nil {
				t.Errorf("Unexpected runner creation error: %s", err)
			}
			for _, v := range ret.Results {
				for _, c := range v.Cases {
					if c.Error != nil {
						t.Errorf(`Test case "%s" raises error: %s`, c.Name, c.Error)
						return
					}
				}
			}
			if ret.Statistics.Skips != tt.skipped {
				t.Errorf("Testing skipped count should be %d, got: %d", tt.skipped, ret.Statistics.Skips)
				return
			}
		})
	}
}
