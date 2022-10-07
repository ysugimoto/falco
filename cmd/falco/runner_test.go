package main

import (
	"errors"
	"os"
	"testing"

	"github.com/ysugimoto/falco/terraform"
)

type mockResolver struct {
	dependency map[string]string
	main       string
}

func (m *mockResolver) MainVCL() (*VCL, error) {
	return &VCL{
		Name: "main.vcl",
		Data: m.main,
	}, nil
}

func (m *mockResolver) Resolve(module string) (*VCL, error) {
	if v, ok := m.dependency[module]; !ok {
		return nil, errors.New(module + " is not defined")
	} else {
		return &VCL{
			Name: module + ".vcl",
			Data: v,
		}, nil
	}
}

func (m *mockResolver) Name() string {
	return ""
}

func loadFromTfJson(fileName string, t *testing.T) ([]Resolver, Fetcher) {
	buf, err := os.ReadFile(fileName)
	if err != nil {
		t.Fatalf("Unexpected error %s reading file %s ", fileName, err)
	}

	services, err := terraform.UnmarshalTerraformPlannedInput(buf)
	if err != nil {
		t.Fatalf("Unexpected error %s unarshalling %s ", fileName, err)
	}

	rslv := NewTerraformResolver(services)
	f := terraform.NewTerraformFetcher(services)
	return rslv, f
}

func TestResolveExternalWithExternalProperties(t *testing.T) {
	for _, fileName := range []string{"../../terraform/data/terraform-valid.json", "../../terraform/data/terraform-valid-weird-name.json"} {
		rslv, f := loadFromTfJson(fileName, t)
		r, err := NewRunner(rslv[0], &Config{V: true}, f)
		if err != nil {
			t.Fatalf("Unexpected runner creation error: %s", err)
			return
		}
		ret, err := r.Run()
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
	r, err := NewRunner(rslv[0], &Config{V: true}, f)
	if err != nil {
		t.Fatalf("Unexpected runner creation error: %s", err)
		return
	}
	ret, err := r.Run()
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
	r, err := NewRunner(rslv[0], &Config{V: true}, f)
	if err != nil {
		t.Fatalf("Unexpected runner creation error: %s", err)
	}
	ret, err := r.Run()
	if err != nil {
		t.Fatalf("Unexpected Run() error: %s", err)
	}

	if ret.Errors != 1 {
		t.Errorf("Errors expects 1, got %d", ret.Errors)
	}
}

func TestResolveIncludeStatement(t *testing.T) {
	mock := &mockResolver{
		dependency: map[string]string{
			"deps01": `
sub foo {
	set req.backend = httpbin_org;
}

sub bar {
	set req.http.Foo = "bar";
}
			`,
		},
		main: `
backend httpbin_org {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "httpbin.org";
  .first_byte_timeout = 20s;
  .max_connections = 500;
  .between_bytes_timeout = 20s;
  .share_key = "xei5lohleex3Joh5ie5uy7du";
  .ssl = true;
  .ssl_sni_hostname = "httpbin.org";
  .ssl_cert_hostname = "httpbin.org";
  .ssl_check_cert = always;
  .min_tls_version = "1.2";
  .max_tls_version = "1.2";
}

include "deps01";

sub vcl_recv {
   #FASTLY RECV
   call foo;
}
		`,
	}
	r, err := NewRunner(mock, &Config{V: true}, nil)
	if err != nil {
		t.Errorf("Unexpected runner creation error: %s", err)
		return
	}
	ret, err := r.Run()
	if err != nil {
		t.Errorf("Unexpected Run() error: %s", err)
		return
	}
	if ret.Infos > 0 {
		t.Errorf("Infos expects 0, got %d", ret.Infos)
	}
	// Above VCL should have one warning that subroutine "bar" is not defined
	if ret.Warnings != 1 {
		t.Errorf("Warning expects 0, got %d", ret.Warnings)
	}
	if ret.Errors > 0 {
		t.Errorf("Errors expects 0, got %d", ret.Errors)
	}
	if len(ret.Vcl.AST.Statements) != 4 {
		t.Errorf("Parsed VCL should have 4 statements, got %d", len(ret.Vcl.AST.Statements))
	}
}

func TestResolveNestedIncludeStatement(t *testing.T) {
	mock := &mockResolver{
		dependency: map[string]string{
			"deps01": `
include "deps02";
			`,
			"deps02": `
sub foo {
	set req.backend = httpbin_org;
}
			`,
		},
		main: `
backend httpbin_org {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "httpbin.org";
  .first_byte_timeout = 20s;
  .max_connections = 500;
  .between_bytes_timeout = 20s;
  .share_key = "xei5lohleex3Joh5ie5uy7du";
  .ssl = true;
  .ssl_sni_hostname = "httpbin.org";
  .ssl_cert_hostname = "httpbin.org";
  .ssl_check_cert = always;
  .min_tls_version = "1.2";
  .max_tls_version = "1.2";
}

include "deps01";

sub vcl_recv {
   #FASTLY RECV
   call foo;
}
		`,
	}
	r, err := NewRunner(mock, &Config{V: true}, nil)
	if err != nil {
		t.Errorf("Unexpected runner creation error: %s", err)
		return
	}
	ret, err := r.Run()
	if err != nil {
		t.Errorf("Unexpected Run() error: %s", err)
		return
	}
	if ret.Infos > 0 {
		t.Errorf("Infos expects 0, got %d", ret.Infos)
	}
	if ret.Warnings > 0 {
		t.Errorf("Warning expects 0, got %d", ret.Warnings)
	}
	if ret.Errors > 0 {
		t.Errorf("Errors expects 0, got %d", ret.Errors)
	}
	if len(ret.Vcl.AST.Statements) != 3 {
		t.Errorf("Parsed VCL should have 3 statements, got %d", len(ret.Vcl.AST.Statements))
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
			resolvers, err := NewFileResolvers(tt.fileName, c)
			if err != nil {
				t.Errorf("Unexpected runner creation error: %s", err)
				return
			}
			r, err := NewRunner(resolvers[0], &Config{V: true}, nil)
			if err != nil {
				t.Errorf("Unexpected runner creation error: %s", err)
				return
			}
			ret, err := r.Run()
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
