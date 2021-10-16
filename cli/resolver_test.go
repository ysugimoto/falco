package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/remote"
	"github.com/ysugimoto/falco/token"
)

var T = token.Token{}

func assert(t *testing.T, actual, expect interface{}) {

	if diff := cmp.Diff(expect, actual,
		// Meta structs ignores Token info
		cmpopts.IgnoreFields(ast.Comment{}, "Token"),
		cmpopts.IgnoreFields(ast.Meta{}, "Token"),
		cmpopts.IgnoreFields(ast.Operator{}),

		// VCL type struct ignores Meta info
		cmpopts.IgnoreFields(ast.Ident{}),
		cmpopts.IgnoreFields(ast.Boolean{}),
		cmpopts.IgnoreFields(ast.Integer{}),
		cmpopts.IgnoreFields(ast.IP{}),
		cmpopts.IgnoreFields(ast.String{}),
		cmpopts.IgnoreFields(ast.Float{}),
		cmpopts.IgnoreFields(ast.RTime{}),

		cmpopts.IgnoreFields(ast.AclDeclaration{}),
		cmpopts.IgnoreFields(ast.AclCidr{}),
		cmpopts.IgnoreFields(ast.BackendDeclaration{}),
		cmpopts.IgnoreFields(ast.BackendProperty{}),
		cmpopts.IgnoreFields(ast.BackendProbeObject{}),
		cmpopts.IgnoreFields(ast.ImportStatement{}),
		cmpopts.IgnoreFields(ast.IncludeStatement{}),
		cmpopts.IgnoreFields(ast.DirectorDeclaration{}),
		cmpopts.IgnoreFields(ast.DirectorProperty{}),
		cmpopts.IgnoreFields(ast.DirectorBackendObject{}),
		cmpopts.IgnoreFields(ast.TableDeclaration{}),
		cmpopts.IgnoreFields(ast.TableProperty{}),
		cmpopts.IgnoreFields(ast.SubroutineDeclaration{}),
		cmpopts.IgnoreFields(ast.DeclareStatement{}),
		cmpopts.IgnoreFields(ast.BlockStatement{}),
		cmpopts.IgnoreFields(ast.SetStatement{}),
		cmpopts.IgnoreFields(ast.InfixExpression{}),
		cmpopts.IgnoreFields(ast.PrefixExpression{}),
		cmpopts.IgnoreFields(ast.GroupedExpression{}),
		cmpopts.IgnoreFields(ast.IfStatement{}, "AlternativeComments"),
		cmpopts.IgnoreFields(ast.UnsetStatement{}),
		cmpopts.IgnoreFields(ast.AddStatement{}),
		cmpopts.IgnoreFields(ast.CallStatement{}),
		cmpopts.IgnoreFields(ast.ErrorStatement{}),
		cmpopts.IgnoreFields(ast.LogStatement{}),
		cmpopts.IgnoreFields(ast.ReturnStatement{}),
		cmpopts.IgnoreFields(ast.SyntheticStatement{}),
		cmpopts.IgnoreFields(ast.SyntheticBase64Statement{}),
		cmpopts.IgnoreFields(ast.IfExpression{}),
		cmpopts.IgnoreFields(ast.FunctionCallExpression{}),
		cmpopts.IgnoreFields(ast.RestartStatement{}),
		cmpopts.IgnoreFields(ast.EsiStatement{}),
	); diff != "" {
		t.Errorf("Assertion error: diff=%s", diff)
	}
}

func comments(c ...string) ast.Comments {
	cs := ast.Comments{}
	for i := range c {
		cs = append(cs, &ast.Comment{
			Value: c[i],
		})
	}
	return cs
}

func TestFileResolver(t *testing.T) {
	t.Run("resolve in root", func(t *testing.T) {
		input := `
include "fixture";
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatal(err)
		}

		r := newResolver()
		r.addIncludePaths("../__fixture__")
		stmt, err := r.Resolve(vcl.Statements, remote.SnippetTypeInit)
		if err != nil {
			t.Fatal(err)
		}

		expect := []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: ast.New(T, 0),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "some_recv",
				},
				Block: &ast.BlockStatement{
					Meta: ast.New(T, 1),
					Statements: []ast.Statement{
						&ast.SetStatement{
							Meta: ast.New(T, 1),
							Ident: &ast.Ident{
								Meta:  ast.New(T, 1),
								Value: "req.http.Fixture",
							},
							Operator: &ast.Operator{
								Meta:     ast.New(T, 1),
								Operator: "=",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "1",
							},
						},
					},
				},
			},
		}

		assert(t, stmt, expect)
	})

	t.Run("resolve in statement", func(t *testing.T) {
		input := `
sub vcl_recv {
	include "statement-fixture";
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatal(err)
		}

		r := newResolver()
		r.addIncludePaths("../__fixture__")
		stmt, err := r.Resolve(vcl.Statements, remote.SnippetTypeInit)
		if err != nil {
			t.Fatal(err)
		}

		expect := []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: ast.New(T, 0),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: ast.New(T, 1),
					Statements: []ast.Statement{
						&ast.SetStatement{
							Meta: ast.New(T, 0),
							Ident: &ast.Ident{
								Meta:  ast.New(T, 0),
								Value: "req.http.Fixture",
							},
							Operator: &ast.Operator{
								Meta:     ast.New(T, 0),
								Operator: "=",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 0),
								Value: "1",
							},
						},
					},
				},
			},
		}

		assert(t, stmt, expect)
	})
}

func TestSnippetResolver(t *testing.T) {
	t.Run("resolve in root", func(t *testing.T) {
		input := `
include "snippet::root";
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatal(err)
		}

		r := newResolver()
		c := `
sub some_recv {
	set req.http.Fixture = "1";
}`
		r.addSnippets(&remote.VCLSnippet{
			Name:    "root",
			Content: &c,
		})
		stmt, err := r.Resolve(vcl.Statements, remote.SnippetTypeInit)
		if err != nil {
			t.Fatal(err)
		}

		expect := []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: ast.New(T, 0),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "some_recv",
				},
				Block: &ast.BlockStatement{
					Meta: ast.New(T, 1),
					Statements: []ast.Statement{
						&ast.SetStatement{
							Meta: ast.New(T, 1),
							Ident: &ast.Ident{
								Meta:  ast.New(T, 1),
								Value: "req.http.Fixture",
							},
							Operator: &ast.Operator{
								Meta:     ast.New(T, 1),
								Operator: "=",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 1),
								Value: "1",
							},
						},
					},
				},
			},
		}

		assert(t, stmt, expect)
	})

	t.Run("resolve in statement", func(t *testing.T) {
		input := `
sub vcl_recv {
	include "snippet::stmt";
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatal(err)
		}

		r := newResolver()
		c := `
set req.http.Fixture = "1";
`
		r.addSnippets(&remote.VCLSnippet{
			Name:    "stmt",
			Content: &c,
		})
		stmt, err := r.Resolve(vcl.Statements, remote.SnippetTypeInit)
		if err != nil {
			t.Fatal(err)
		}

		expect := []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: ast.New(T, 0),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: ast.New(T, 1, ast.Comments{}),
					Statements: []ast.Statement{
						&ast.SetStatement{
							Meta: ast.New(T, 0),
							Ident: &ast.Ident{
								Meta:  ast.New(T, 0),
								Value: "req.http.Fixture",
							},
							Operator: &ast.Operator{
								Meta:     ast.New(T, 0),
								Operator: "=",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 0),
								Value: "1",
							},
						},
					},
				},
			},
		}

		assert(t, stmt, expect)
	})

	t.Run("resolve in statement macro", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatal(err)
		}

		r := newResolver()
		c := `
set req.http.Fixture = "1";
`
		r.addSnippets(&remote.VCLSnippet{
			Name:    "stmt",
			Content: &c,
			Type:    remote.SnippetTypeRecv,
		})
		r.addSnippets(&remote.VCLSnippet{
			Name:    "stmt2",
			Content: &c,
			Type:    remote.SnippetTypeFetch,
		})
		stmt, err := r.Resolve(vcl.Statements, remote.SnippetTypeInit)
		if err != nil {
			t.Fatal(err)
		}

		expect := []ast.Statement{
			&ast.SubroutineDeclaration{
				Meta: ast.New(T, 0),
				Name: &ast.Ident{
					Meta:  ast.New(T, 0),
					Value: "vcl_recv",
				},
				Block: &ast.BlockStatement{
					Meta: ast.New(T, 1, comments(), comments(), comments("#FASTLY recv")),
					Statements: []ast.Statement{
						&ast.SetStatement{
							Meta: ast.New(T, 0),
							Ident: &ast.Ident{
								Meta:  ast.New(T, 0),
								Value: "req.http.Fixture",
							},
							Operator: &ast.Operator{
								Meta:     ast.New(T, 0),
								Operator: "=",
							},
							Value: &ast.String{
								Meta:  ast.New(T, 0),
								Value: "1",
							},
						},
					},
				},
			},
		}

		assert(t, stmt, expect)
	})
}
