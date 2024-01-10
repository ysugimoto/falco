package transport

import (
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	flchttp "github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

var backends = `
backend test01 {
  .host = "example01.com";
  .port = "443";
}

backend test02 {
  .host = "example02.com";
  .port = "443";
}

backend test03 {
  .host = "example03.com";
  .port = "443";
}
`

func setup() (*context.Context, error) {
	vcl, err := parser.New(
		lexer.NewFromString(backends, lexer.WithFile("Test.transport.backends")),
	).ParseVCL()
	if err != nil {
		return nil, err
	}
	ctx := &context.Context{
		RequestHash: &value.String{
			Value: "/?foo=bar",
		},
		ClientIdentity: &value.String{
			Value: "127.0.0.1",
		},
		Backends: make(map[string]*value.Backend),
	}
	for _, decl := range vcl.Statements {
		if v, ok := decl.(*ast.BackendDeclaration); ok {
			ctx.Backends[v.Name.Value] = &value.Backend{
				Value:   v,
				Healthy: &atomic.Bool{},
			}
			ctx.Backends[v.Name.Value].Healthy.Store(true)
		}
	}
	return ctx, nil
}

func TestGetDirectorConfig(t *testing.T) {
	director := `
director test random {
  .quorum  = 50%;
  .retries = 3;
  { .backend = test01; .weight = 2; }
  { .backend = test02; .weight = 1; }
  { .backend = test03; .weight = 1; }
}
`
	ctx, err := setup()
	if err != nil {
		t.Errorf("Failed to setup context: %s", err)
		return
	}
	vcl, err := parser.New(lexer.NewFromString(director)).ParseVCL()
	if err != nil {
		t.Errorf("Failed to parse director specification VCL: %s", err)
		return
	}

	d, err := GetDirector(ctx, vcl.Statements[0].(*ast.DirectorDeclaration))
	if err != nil {
		t.Errorf("Failed to get director struct: %s", err)
		return
	}
	expect := &flchttp.Director{
		Quorum:  50,
		Retries: 3,
		Name:    "test",
		Type:    "random",
		Backends: []*flchttp.DirectorBackend{
			{Backend: ctx.Backends["test01"], Weight: 2},
			{Backend: ctx.Backends["test02"], Weight: 1},
			{Backend: ctx.Backends["test03"], Weight: 1},
		},
	}
	if diff := cmp.Diff(expect, d, cmpopts.IgnoreFields(value.Backend{}, "Healthy")); diff != "" {
		t.Errorf("GetDirector returns diff: %s", diff)
	}
}

func TestGetDirectorConfigShield(t *testing.T) {
	director := "director test shield { }"
	ctx, err := setup()
	if err != nil {
		t.Errorf("Failed to setup context: %s", err)
		return
	}
	vcl, err := parser.New(lexer.NewFromString(director)).ParseVCL()
	if err != nil {
		t.Errorf("Failed to parse director specification VCL: %s", err)
		return
	}

	d, err := GetDirector(ctx, vcl.Statements[0].(*ast.DirectorDeclaration))
	if err != nil {
		t.Errorf("Failed to get director struct: %s", err)
		return
	}

	expect := &flchttp.Director{
		Quorum:  0,
		Retries: 0,
		Name:    "test",
		Type:    "shield",
	}
	if diff := cmp.Diff(expect, d, cmpopts.IgnoreFields(value.Backend{}, "Healthy")); diff != "" {
		t.Errorf("GetDirector returns diff: %s", diff)
	}
}
