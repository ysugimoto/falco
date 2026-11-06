package interpreter

import (
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/v2/ast"
	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/lexer"
	"github.com/ysugimoto/falco/v2/parser"
	"github.com/ysugimoto/falco/v2/resolver"
)

type includeResolver struct {
	dependency map[string]string
}

func (r *includeResolver) MainVCL() (*resolver.VCL, error) {
	return &resolver.VCL{Name: "main.vcl"}, nil
}

func (r *includeResolver) Resolve(stmt *ast.IncludeStatement) (*resolver.VCL, error) {
	data, ok := r.dependency[stmt.Module.Value]
	if !ok {
		return nil, errors.New(stmt.Module.Value + " is not defined")
	}
	return &resolver.VCL{
		Name: stmt.Module.Value + ".vcl",
		Data: data,
	}, nil
}

func (r *includeResolver) Name() string           { return "" }
func (r *includeResolver) IncludePaths() []string { return []string{} }

func resolveIncludes(t *testing.T, main string, dependency map[string]string) ([]ast.Statement, error) {
	t.Helper()

	vcl, err := parser.New(lexer.NewFromString(main)).ParseVCL()
	if err != nil {
		t.Fatalf("unexpected parser error: %s", err)
	}

	ip := New()
	ip.ctx = context.New(context.WithResolver(&includeResolver{dependency: dependency}))
	return ip.resolveIncludeStatement(vcl.Statements, true)
}

func TestResolveRecursiveIncludeStatement(t *testing.T) {
	main := `include "deps01";`

	tests := []struct {
		name       string
		dependency map[string]string
	}{
		{
			name: "module includes itself",
			dependency: map[string]string{
				"deps01": `include "deps01";`,
			},
		},
		{
			name: "modules include each other",
			dependency: map[string]string{
				"deps01": `include "deps02";`,
				"deps02": `include "deps01";`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveIncludes(t, main, tt.dependency)
			if err == nil {
				t.Fatal("Expected error but got nil")
			}
			if !strings.Contains(err.Error(), "included recursively") {
				t.Errorf("Error expects to report recursion but got %s", err)
			}
		})
	}
}

func TestIncludeSameModuleTwice(t *testing.T) {
	// The same module included twice is not a loop, and both inclusions stand.
	main := `
include "deps01";
include "deps01";
	`
	dependency := map[string]string{
		"deps01": `
sub func {
	set req.http.Foo = "bar";
}
		`,
	}

	statements, err := resolveIncludes(t, main, dependency)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(statements) != 2 {
		t.Errorf("Expects 2 statements but got %d", len(statements))
	}
}
