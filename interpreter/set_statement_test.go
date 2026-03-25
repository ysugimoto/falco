package interpreter

import (
	ghttp "net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestSetStatementOutcome(t *testing.T) {
	t.Run("set local var to null", func(t *testing.T) {
		ip := setupInterpreter(t)
		declare(t, ip, "var.NULL", "STRING")
		declare(t, ip, "var.foo", "STRING")
		set(t, ip, &ast.Ident{Value: "var.foo"}, &ast.Ident{Value: "var.NULL"})
		v := getLocalVar(t, ip, "var.foo")
		assertValuesEqual(t, &value.String{Value: ""}, v)
	})

	t.Run("set local val to concatenated string with null element", func(t *testing.T) {
		ip := setupInterpreter(t)
		declare(t, ip, "var.NULL", "STRING")
		declare(t, ip, "var.dst", "STRING")
		set(t, ip, &ast.Ident{Value: "var.dst"}, &ast.InfixExpression{
			Left:     &ast.String{Value: "prefix-"},
			Operator: "+",
			Right:    &ast.Ident{Value: "var.NULL"},
		})
		v := getLocalVar(t, ip, "var.dst")
		assertValuesEqual(t, &value.String{Value: "prefix-"}, v)
	})

	t.Run("initialize http header to null", func(t *testing.T) {
		ip := setupInterpreter(t)
		declare(t, ip, "var.NULL", "STRING")
		set(t, ip, &ast.Ident{Value: "req.http.x-header"}, &ast.Ident{Value: "var.NULL"})
		log(t, ip, &ast.Ident{Value: "req.http.x-header"})
		v := getVar(t, ip, "req.http.x-header")
		assertValuesEqual(t, &value.String{IsNotSet: true}, v)
		assertStringsEqual(t, "(null)", ip.process.Logs[0].Message)
	})

	t.Run("set header to concatenated string with null element", func(t *testing.T) {
		ip := setupInterpreter(t)
		declare(t, ip, "var.NULL", "STRING")
		set(t, ip, &ast.Ident{Value: "req.http.x-header"}, &ast.InfixExpression{
			Left:     &ast.String{Value: "prefix-"},
			Operator: "+",
			Right:    &ast.Ident{Value: "var.NULL"},
		})
		v := getVar(t, ip, "req.http.x-header")
		assertValuesEqual(t, &value.String{Value: "prefix-(null)"}, v)
	})

	t.Run("set header field to null", func(t *testing.T) {
		ip := setupInterpreter(t)
		declare(t, ip, "var.NULL", "STRING")
		set(t, ip, &ast.Ident{Value: "req.http.x-header:field"}, &ast.Ident{Value: "var.NULL"})
		log(t, ip, &ast.Ident{Value: "req.http.x-header:field"})
		v := getVar(t, ip, "req.http.x-header:field")
		assertValuesEqual(t, &value.String{Value: ""}, v)
		assertStringsEqual(t, "", ip.process.Logs[0].Message)
	})

	t.Run("reset preinitialized header field to null", func(t *testing.T) {
		ip := setupInterpreter(t)
		declare(t, ip, "var.NULL", "STRING")
		set(t, ip, &ast.Ident{Value: "req.http.x-header:preserved"}, &ast.String{Value: "preserved-value"})
		set(t, ip, &ast.Ident{Value: "req.http.x-header:field"}, &ast.String{Value: "foo"})
		set(t, ip, &ast.Ident{Value: "req.http.x-header:field"}, &ast.Ident{Value: "var.NULL"})
		log(t, ip, &ast.Ident{Value: "req.http.x-header:field"})
		assertValuesEqual(t, &value.String{Value: ""}, getVar(t, ip, "req.http.x-header:field"))
		assertValuesEqual(t, &value.String{Value: "preserved-value"}, getVar(t, ip, "req.http.x-header:preserved"))
		assertStringsEqual(t, "", ip.process.Logs[0].Message)
	})

	t.Run("set header field to concatenated string with null element", func(t *testing.T) {
		ip := setupInterpreter(t)
		declare(t, ip, "var.NULL", "STRING")
		set(t, ip, &ast.Ident{Value: "req.http.x-header:foo"}, &ast.InfixExpression{
			Left:     &ast.String{Value: "prefix-"},
			Operator: "+",
			Right:    &ast.Ident{Value: "var.NULL"},
		})
		v := getVar(t, ip, "req.http.x-header:foo")
		assertValuesEqual(t, &value.String{Value: "prefix-"}, v)
	})

	t.Run("reset existing header to null", func(t *testing.T) {
		ip := setupInterpreter(t)
		declare(t, ip, "var.NULL", "STRING")
		set(t, ip, &ast.Ident{Value: "req.http.x-header"}, &ast.String{Value: "foo"})
		assertIntsEqual(t, 1, len(ip.ctx.Request.Header))
		set(t, ip, &ast.Ident{Value: "req.http.x-header"}, &ast.Ident{Value: "var.NULL"})
		assertIntsEqual(t, 0, len(ip.ctx.Request.Header))
		log(t, ip, &ast.Ident{Value: "req.http.x-header"})
		v, err := ip.vars.Get(context.RecvScope, "req.http.x-header")
		if err != nil {
			t.Errorf("var.foo must be declared: %s", err)
			return
		}
		assertValuesEqual(t, &value.String{IsNotSet: true}, v)
		assertStringsEqual(t, "(null)", ip.process.Logs[0].Message)
	})

	t.Run("json.excape of null to local var", func(t *testing.T) {
		ip := setupInterpreter(t)
		declare(t, ip, "var.NULL", "STRING")
		declare(t, ip, "var.escaped", "STRING")
		set(t, ip, &ast.Ident{Value: "var.escaped"}, &ast.FunctionCallExpression{
			Function:  &ast.Ident{Value: "json.escape"},
			Arguments: []ast.Expression{&ast.Ident{Value: "var.NULL"}},
		})
		assertValuesEqual(t, &value.String{Value: ""}, getLocalVar(t, ip, "var.escaped"))
	})

	t.Run("json.excape of null to http header", func(t *testing.T) {
		ip := setupInterpreter(t)
		declare(t, ip, "var.NULL", "STRING")
		escapeOfNull := &ast.FunctionCallExpression{
			Function:  &ast.Ident{Value: "json.escape"},
			Arguments: []ast.Expression{&ast.Ident{Value: "var.NULL"}},
		}
		set(t, ip, &ast.Ident{Value: "req.http.x-header"}, escapeOfNull)
		assertValuesEqual(t, &value.String{Value: ""}, getVar(t, ip, "req.http.x-header"))
		log(t, ip, escapeOfNull)
		assertStringsEqual(t, "", ip.process.Logs[0].Message)
	})

}

// *******************************************
// Internal API
// *******************************************

func getLocalVar(t *testing.T, ip *Interpreter, name string) value.Value {
	t.Helper()
	v, err := ip.localVars.Get(name)
	if err != nil {
		t.Errorf("%s: Failed to get local variable '%s': %s", t.Name(), name, err)
	}
	return v
}

func getVar(t *testing.T, ip *Interpreter, name string) value.Value {
	t.Helper()
	v, err := ip.vars.Get(context.RecvScope, name)
	if err != nil {
		t.Errorf("%s: Failed to get variable '%s' from scope '%s': %s", t.Name(), name, context.RecvScope, err)
	}
	return v
}

func log(t *testing.T, ip *Interpreter, value ast.Expression) {
	t.Helper()
	if err := ip.ProcessLogStatement(&ast.LogStatement{
		Meta:  &ast.Meta{},
		Value: value,
	}); err != nil {
		t.Errorf("Failed to log: %s", err)
	}
}

func declare(t *testing.T, ip *Interpreter, name, valueType string) {
	t.Helper()
	if err := ip.localVars.Declare(name, valueType); err != nil {
		t.Errorf("Failed to declare %s of type %s: %s", name, valueType, err)
	}
}

func set(t *testing.T, ip *Interpreter, ident *ast.Ident, value ast.Expression) {
	t.Helper()
	stmt := &ast.SetStatement{
		Meta:     &ast.Meta{},
		Ident:    ident,
		Operator: &ast.Operator{Operator: "="},
		Value:    value,
	}
	if err := ip.ProcessSetStatement(stmt); err != nil {
		t.Errorf("Failed to set %s: %s", ident.Value, err)
	}
}

func assertStringsEqual(t *testing.T, expect, actual any) {
	t.Helper()
	if expect != actual {
		t.Errorf(`%v: Expected "%v", got "%v"`, t.Name(), expect, actual)
	}
}

func assertIntsEqual(t *testing.T, expect, actual int) {
	t.Helper()
	if expect != actual {
		t.Errorf(`%v: Expected "%v", got "%v"`, t.Name(), expect, actual)
	}
}

func assertValuesEqual(t *testing.T, expect, actual value.Value) {
	t.Helper()
	if expect.Type() != actual.Type() {
		t.Errorf("%s: type unmatch, expect %s, got %s", t.Name(), expect.Type(), actual.Type())
		return
	}
	if diff := cmp.Diff(expect, actual); diff != "" {
		t.Errorf("%s: Value assertion error, diff: %s", t.Name(), diff)
	}
}

func setupInterpreter(t *testing.T) *Interpreter {
	name := t.Name()
	ip := New(nil)
	ip.ctx = context.New()
	ip.SetScope(context.RecvScope)
	req, err := http.NewRequest(ghttp.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Errorf("%s: unexpected error returned: %s", name, err)
	}
	ip.ctx.Request = req
	ip.ctx.BackendRequest = req
	return ip
}
