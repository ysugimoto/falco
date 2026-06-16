package limitations

import (
	"strings"
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

// callTreeContext parses VCL and registers its subroutines the way the
// interpreter does, so the call-tree limit can be exercised in isolation.
func callTreeContext(t *testing.T, vcl string) *context.Context {
	t.Helper()
	v, err := parser.New(lexer.NewFromString(vcl)).ParseVCL()
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	ctx := context.New()
	for _, s := range v.Statements {
		sub, ok := s.(*ast.SubroutineDeclaration)
		if !ok {
			continue
		}
		if sub.ReturnType != nil {
			ctx.SubroutineFunctions[sub.Name.Value] = sub
		} else {
			ctx.Subroutines[sub.Name.Value] = sub
		}
	}
	return ctx
}

func TestCheckFastlyCallTreeLimit(t *testing.T) {
	t.Run("flat tree is well under the limit", func(t *testing.T) {
		vcl := "sub leaf {}\nsub vcl_recv {\n" +
			strings.Repeat("  call leaf;\n", 100) + "}"
		if err := CheckFastlyCallTreeLimit(callTreeContext(t, vcl)); err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("nested tree under the limit passes", func(t *testing.T) {
		// mid expands to 100, top to 100 * (1 + 100) = 10100.
		vcl := "sub leaf {}\n" +
			"sub mid {\n" + strings.Repeat("  call leaf;\n", 100) + "}\n" +
			"sub top {\n" + strings.Repeat("  call mid;\n", 100) + "}"
		if err := CheckFastlyCallTreeLimit(callTreeContext(t, vcl)); err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})

	t.Run("nested tree over the limit is rejected", func(t *testing.T) {
		// mid expands to 200, top to 200 * (1 + 200) = 40200, over 25000.
		vcl := "sub leaf {}\n" +
			"sub mid {\n" + strings.Repeat("  call leaf;\n", 200) + "}\n" +
			"sub top {\n" + strings.Repeat("  call mid;\n", 200) + "}"
		err := CheckFastlyCallTreeLimit(callTreeContext(t, vcl))
		if err == nil {
			t.Fatal("expected error but got nil")
		}
		if !strings.Contains(err.Error(), "Too many sub calls") {
			t.Errorf("unexpected message: %s", err)
		}
		if !strings.Contains(err.Error(), "top") {
			t.Errorf("error should name the offending subroutine: %s", err)
		}
	})

	t.Run("calls inside nested blocks are counted", func(t *testing.T) {
		// Each call sits inside an if/else or switch block to make sure the
		// walker descends into them.
		body := strings.Repeat(
			"  if (req.http.X) { call leaf; } else { call leaf; }\n", 200,
		)
		vcl := "sub leaf {}\n" +
			"sub mid {\n" + body + "}\n" +
			"sub top {\n" + strings.Repeat("  call mid;\n", 200) + "}"
		if err := CheckFastlyCallTreeLimit(callTreeContext(t, vcl)); err == nil {
			t.Error("expected error but got nil")
		}
	})

	t.Run("recursive VCL terminates without error", func(t *testing.T) {
		// Recursion is rejected by the runtime call-stack guard, not here; the
		// static walk must simply not loop forever.
		vcl := "sub a { call b; }\nsub b { call a; }"
		if err := CheckFastlyCallTreeLimit(callTreeContext(t, vcl)); err != nil {
			t.Errorf("unexpected error: %s", err)
		}
	})
}
