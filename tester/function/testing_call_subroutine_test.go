package function

import (
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter"
	iCtx "github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

// newCallSubCtx returns a minimal context with all subroutine maps initialised
// so that resolveSubroutine never panics on a nil-map lookup.
func newCallSubCtx() *iCtx.Context {
	return &iCtx.Context{
		Subroutines:                  make(map[string]*ast.SubroutineDeclaration),
		SubroutineFunctions:          make(map[string]*ast.SubroutineDeclaration),
		MockedSubroutines:            make(map[string]*ast.SubroutineDeclaration),
		MockedFunctioncalSubroutines: make(map[string]*ast.SubroutineDeclaration),
	}
}

// parseSub is a helper that parses a single subroutine declaration from VCL
// source and returns the AST node.
func parseSub(t *testing.T, src string) *ast.SubroutineDeclaration {
	t.Helper()
	vcl, err := parser.New(lexer.NewFromString(src)).ParseVCL()
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return vcl.Statements[0].(*ast.SubroutineDeclaration)
}

// --- Testing_call_subroutine_Validate ---

func Test_call_subroutine_Validate(t *testing.T) {
	tests := []struct {
		name    string
		args    []value.Value
		isError bool
	}{
		{
			name:    "no arguments",
			args:    []value.Value{},
			isError: true,
		},
		{
			name:    "first arg not STRING",
			args:    []value.Value{&value.Integer{Value: 42}},
			isError: true,
		},
		{
			name:    "first arg is STRING — valid",
			args:    []value.Value{&value.String{Value: "vcl_recv"}},
			isError: false,
		},
		{
			name: "first arg STRING with extra args — valid",
			args: []value.Value{
				&value.String{Value: "my_sub"},
				&value.String{Value: "/path"},
			},
			isError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Testing_call_subroutine_Validate(tt.args)
			if tt.isError && err == nil {
				t.Errorf("expected error but got nil")
			} else if !tt.isError && err != nil {
				t.Errorf("unexpected error: %s", err)
			}
		})
	}
}

// --- Testing_call_subroutine: undefined subroutine ---

func Test_call_subroutine_undefined(t *testing.T) {
	ctx := newCallSubCtx()
	i := interpreter.New()

	_, err := Testing_call_subroutine(ctx, i, &value.String{Value: "no_such_sub"})
	if err == nil {
		t.Errorf("expected error for undefined subroutine but got nil")
	}
}

// --- Testing_call_subroutine: argument-count mismatch ---

func Test_call_subroutine_arg_count_mismatch(t *testing.T) {
	sub := parseSub(t, `sub my_func(STRING var.a, STRING var.b) BOOL {
  return true;
}`)

	ctx := newCallSubCtx()
	ctx.SubroutineFunctions["my_func"] = sub
	i := interpreter.New()

	t.Run("too few args", func(t *testing.T) {
		_, err := Testing_call_subroutine(
			ctx, i,
			&value.String{Value: "my_func"},
			&value.String{Value: "/only-one"}, // one arg, need two
		)
		if err == nil {
			t.Errorf("expected error for too-few arguments but got nil")
		}
	})

	t.Run("too many args", func(t *testing.T) {
		_, err := Testing_call_subroutine(
			ctx, i,
			&value.String{Value: "my_func"},
			&value.String{Value: "/a"},
			&value.String{Value: "/b"},
			&value.String{Value: "/extra"}, // three args, need two
		)
		if err == nil {
			t.Errorf("expected error for too-many arguments but got nil")
		}
	})

	t.Run("scoped subroutine with unexpected args", func(t *testing.T) {
		scopedSub := parseSub(t, `sub vcl_recv {
#FASTLY RECV
  return(pass);
}`)
		ctx2 := newCallSubCtx()
		ctx2.Subroutines["vcl_recv"] = scopedSub

		_, err := Testing_call_subroutine(
			ctx2, i,
			&value.String{Value: "vcl_recv"},
			&value.String{Value: "/unexpected"}, // scoped sub takes 0 params
		)
		if err == nil {
			t.Errorf("expected error passing args to zero-param scoped subroutine but got nil")
		}
	})
}
