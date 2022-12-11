package interpreter

import (
	"testing"

	"net/http"
	"net/http/httptest"

	"github.com/google/go-cmp/cmp"
	_ "github.com/k0kubun/pp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func assertInterpreter(t *testing.T, vcl string, scope context.Scope, assertions map[string]value.Value) {
	p, err := parser.New(lexer.NewFromString(vcl)).ParseVCL()
	if err != nil {
		t.Errorf("VCL parsing error: %s", err)
		return
	}
	ctx, err := context.New(p)
	if err != nil {
		t.Errorf("Context creation error: %s", err)
		return
	}
	ip := New(ctx)
	if err := ip.Process(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "http://localhost", nil),
	); err != nil {
		t.Errorf("Interpreter process error: %s", err)
		return
	}

	for name, val := range assertions {
		v, err := ip.vars.Get(scope, name)
		if err != nil {
			t.Errorf("Value get error: %s", err)
			return
		} else if v == nil || v == value.Null {
			t.Errorf("Value %s is nil", name)
			return
		}
		if diff := cmp.Diff(val, v); diff != "" {
			t.Errorf("Value asserion error, diff: %s", diff)
		}
	}
}

func assertValue(t *testing.T, name string, expect, actual value.Value) {
	if expect.Type() != actual.Type() {
		t.Errorf("%s type unmatch, expect %s, got %s", name, expect.Type(), actual.Type())
		return
	}
	if diff := cmp.Diff(expect, actual); diff != "" {
		t.Errorf("Value asserion error, diff: %s", diff)
	}
}
