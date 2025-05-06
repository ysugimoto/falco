package tester

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func TestGetMetadata(t *testing.T) {
	tests := []struct {
		name   string
		vcl    string
		expect *Metadata
	}{
		{
			name: "basic metadata",
			vcl: `
// @suite: basic metadata test
// @scope: recv
sub test_subroutine {}
`,
			expect: &Metadata{
				Name:   "basic metadata test",
				Scopes: []context.Scope{context.RecvScope},
			},
		},
		{
			name: "use subroutine name when suite annotation is not found",
			vcl: `
// @scope: recv
sub test_subroutine {}
`,
			expect: &Metadata{
				Name:   "test_subroutine",
				Scopes: []context.Scope{context.RecvScope},
			},
		},
		{
			name: "default scope is Recv when scope annotation is not found",
			vcl: `
// @suite: metadata test
sub test_subroutine {}
`,
			expect: &Metadata{
				Name:   "metadata test",
				Scopes: []context.Scope{context.RecvScope},
			},
		},
		{
			name: "multiple scopes",
			vcl: `
// @suite: metadata test
// @scope: fetch,pass,log
sub test_subroutine {}
`,
			expect: &Metadata{
				Name:   "metadata test",
				Scopes: []context.Scope{context.FetchScope, context.PassScope, context.LogScope},
			},
		},
		{
			name: "skipped",
			vcl: `
// @suite: metadata test
// @scope: recv
// @skip
sub test_subroutine {}
`,
			expect: &Metadata{
				Name:   "metadata test",
				Scopes: []context.Scope{context.RecvScope},
				Skip:   true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vcl, err := parser.New(lexer.NewFromString(tt.vcl)).ParseVCL()
			if err != nil {
				t.Errorf("VCL parser error: %s", err)
				return
			}
			sub := vcl.Statements[0].(*ast.SubroutineDeclaration)
			actual := getTestMetadata(sub)
			if diff := cmp.Diff(tt.expect, actual); diff != "" {
				t.Errorf("Parsed metadata mismatch, diff=%s", diff)
			}
		})
	}
}
