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
				Tags:   []Tag{},
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
				Tags:   []Tag{},
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
				Tags:   []Tag{},
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
				Tags:   []Tag{},
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
				Tags:   []Tag{},
			},
		},
		{
			name: "tagged",
			vcl: `
// @suite: metadata test
// @scope: recv
// @tag: prod,!stg
sub test_subroutine {}
`,
			expect: &Metadata{
				Name:   "metadata test",
				Scopes: []context.Scope{context.RecvScope},
				Tags: []Tag{
					{Name: "prod"},
					{Name: "stg", Inverse: true},
				},
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

// https://github.com/ysugimoto/falco/issues/457
func TestTagsMatch(t *testing.T) {
	tests := []struct {
		name   string
		tag    []string
		tags   []Tag
		expect bool
	}{
		{
			name:   "no tags",
			tag:    []string{"prod"},
			tags:   []Tag{},
			expect: false,
		},
		{
			name: "singular tag match",
			tag:  []string{"prod"},
			tags: []Tag{
				{Name: "prod"},
			},
			expect: true,
		},
		{
			name: "singular inversed tag unmatch",
			tag:  []string{"prod"},
			tags: []Tag{
				{Name: "prod", Inverse: true},
			},
			expect: false,
		},
		{
			name: "singular inversed tag match",
			tag:  []string{"dev"},
			tags: []Tag{
				{Name: "prod", Inverse: true},
			},
			expect: true,
		},
		{
			name: "multiple tag match",
			tag:  []string{"stg"},
			tags: []Tag{
				{Name: "prod"},
				{Name: "stg"},
			},
			expect: true,
		},
		{
			name: "multiple inversed tag unmatch",
			tag:  []string{"prod"},
			tags: []Tag{
				{Name: "prod", Inverse: true},
				{Name: "stg"},
			},
			expect: false,
		},
		{
			name: "multiple inversed tag match",
			tag:  []string{"stg"},
			tags: []Tag{
				{Name: "prod", Inverse: true},
				{Name: "stg", Inverse: true},
			},
			expect: true,
		},
		{
			name: "always match",
			tag:  []string{"prod"},
			tags: []Tag{
				{Name: "prod", Inverse: true},
				{Name: "prod"},
			},
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Metadata{Tags: tt.tags}
			actual := m.MatchTags(tt.tag)
			if diff := cmp.Diff(tt.expect, actual); diff != "" {
				t.Errorf("Tags.Match result unmatch, diff=%s", diff)
			}
		})
	}
}
