package interpreter

import (
	"testing"

	"net/http"
	"net/http/httptest"

	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/simulator/context"
	"github.com/ysugimoto/falco/simulator/variable"
)

func assertInterpreter(t *testing.T, vcl string, assertions map[string]variable.Value) {
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
		v := ip.vars.Get(name)
		if v == nil {
			t.Errorf("Variable %s is nil", name)
			return
		}
		if v.Value == nil {
			t.Errorf("Variable %s value is nil", name)
			return
		}
		if v.Value.Type() != val.Type() {
			t.Errorf("Variable %s type unmatch, expect %s, got %s", name, val.Type(), v.Value.Type())
			return
		}
		if v.Value.String() != val.String() {
			t.Errorf("Variable %s value unmatch, expect %v, got %v", name, val.String(), v.Value.String())
			return
		}
	}
}

func assertValue(t *testing.T, name string, expect, actual variable.Value) {
	if expect.Type() != actual.Type() {
		t.Errorf("%s type unmatch, expect %s, got %s", name, expect.Type(), actual.Type())
		return
	}
	if expect.String() != actual.String() {
		t.Errorf("%s value unmatch, expect %v, got %v", name, expect.String(), actual.String())
		return
	}
}

