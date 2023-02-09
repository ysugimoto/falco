package main

import (
	"os"
	"testing"

	"github.com/ysugimoto/falco/resolver"
	"github.com/ysugimoto/falco/terraform"
)

func loadFromTfJson(fileName string, t *testing.T) ([]resolver.Resolver, Fetcher) {
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
		r, err := NewRunner(&Config{V: true}, f)
		if err != nil {
			t.Fatalf("Unexpected runner creation error: %s", err)
			return
		}
		ret, err := r.Run(rslv[0])
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
	r, err := NewRunner(&Config{V: true}, f)
	if err != nil {
		t.Fatalf("Unexpected runner creation error: %s", err)
		return
	}
	ret, err := r.Run(rslv[0])
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
	r, err := NewRunner(&Config{V: true}, f)
	if err != nil {
		t.Fatalf("Unexpected runner creation error: %s", err)
	}
	ret, err := r.Run(rslv[0])
	if err != nil {
		t.Fatalf("Unexpected Run() error: %s", err)
	}

	if ret.Errors != 1 {
		t.Errorf("Errors expects 1, got %d", ret.Errors)
	}
}

// Adds a test for all the example code in the repo to make sure we don't accidentally
// break those as they are the first thing someone might try on the repo.
func TestRepositoryExamples(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		errors   int
		warnings int
		infos    int
	}{
		{
			name:     "example 1",
			fileName: "../../examples/default01.vcl",
			errors:   0,
			warnings: 0,
			infos:    0,
		},
		{
			name:     "example 2",
			fileName: "../../examples/default02.vcl",
			errors:   1,
			warnings: 0,
			infos:    0,
		},
		{
			name:     "example 3",
			fileName: "../../examples/default03.vcl",
			errors:   0,
			warnings: 0,
			infos:    1,
		},
		{
			name:     "example 4",
			fileName: "../../examples/default04.vcl",
			errors:   0,
			warnings: 0,
			infos:    1,
		},
	}

	c := &Config{V: true}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolvers, err := resolver.NewFileResolvers(tt.fileName, c.IncludePaths)
			if err != nil {
				t.Errorf("Unexpected runner creation error: %s", err)
				return
			}
			r, err := NewRunner(&Config{V: true}, nil)
			if err != nil {
				t.Errorf("Unexpected runner creation error: %s", err)
				return
			}
			ret, err := r.Run(resolvers[0])
			if tt.errors != 0 {
				if err == nil {
					t.Errorf("Expected Run() to generate an error")
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
