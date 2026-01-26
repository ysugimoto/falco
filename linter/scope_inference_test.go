package linter

import (
	"testing"

	"github.com/ysugimoto/falco/linter/context"
	"github.com/ysugimoto/falco/parser"

	"github.com/ysugimoto/falco/lexer"
)

func TestScopeInference(t *testing.T) {
	t.Run("infers scope from single Fastly subroutine caller", func(t *testing.T) {
		// to_origin uses req.backend.is_origin which is only available in MISS/PASS/FETCH
		// It's called from vcl_miss, so scope should be inferred as MISS
		input := `
sub to_origin {
  if (req.backend.is_origin) {
    set bereq.http.CDN = "Fastly";
  }
}

sub vcl_miss {
  #FASTLY MISS
  call to_origin;
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatalf("unexpected parser error: %s", err)
		}

		l := New(testConfig)
		ctx := context.New()
		l.lint(vcl, ctx)

		// Should have no errors - scope is inferred from vcl_miss
		for _, e := range l.Errors {
			if e.Severity == ERROR {
				t.Errorf("unexpected error: %s", e.Message)
			}
		}

		// Assert the inferred scope
		if sub, ok := ctx.Subroutines["to_origin"]; !ok {
			t.Errorf("to_origin subroutine not found in context")
		} else if sub.Scopes != context.MISS {
			t.Errorf("expected to_origin scope to be MISS (%d), got %d", context.MISS, sub.Scopes)
		}
	})

	t.Run("infers scope from multiple Fastly subroutine callers", func(t *testing.T) {
		// to_origin is called from both vcl_miss and vcl_pass
		// Scope should be inferred as MISS | PASS
		input := `
sub to_origin {
  if (req.backend.is_origin) {
    set bereq.http.CDN = "Fastly";
  }
}

sub vcl_miss {
  #FASTLY MISS
  call to_origin;
}

sub vcl_pass {
  #FASTLY PASS
  call to_origin;
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatalf("unexpected parser error: %s", err)
		}

		l := New(testConfig)
		ctx := context.New()
		l.lint(vcl, ctx)

		// Should have no errors
		for _, e := range l.Errors {
			if e.Severity == ERROR {
				t.Errorf("unexpected error: %s", e.Message)
			}
		}

		// Assert the inferred scope is MISS | PASS
		expectedScope := context.MISS | context.PASS
		if sub, ok := ctx.Subroutines["to_origin"]; !ok {
			t.Errorf("to_origin subroutine not found in context")
		} else if sub.Scopes != expectedScope {
			t.Errorf("expected to_origin scope to be MISS|PASS (%d), got %d", expectedScope, sub.Scopes)
		}
	})

	t.Run("infers scope through transitive calls", func(t *testing.T) {
		// helper_b is called from helper_a which is called from vcl_miss
		// Scope should propagate: vcl_miss -> helper_a -> helper_b
		input := `
sub helper_b {
  set bereq.http.X-Helper = "B";
}

sub helper_a {
  call helper_b;
  set bereq.http.X-Helper = "A";
}

sub vcl_miss {
  #FASTLY MISS
  call helper_a;
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatalf("unexpected parser error: %s", err)
		}

		l := New(testConfig)
		ctx := context.New()
		l.lint(vcl, ctx)

		// Should have no errors - scope propagates through call chain
		for _, e := range l.Errors {
			if e.Severity == ERROR {
				t.Errorf("unexpected error: %s", e.Message)
			}
		}

		// Assert both helpers have MISS scope propagated
		if sub, ok := ctx.Subroutines["helper_a"]; !ok {
			t.Errorf("helper_a subroutine not found in context")
		} else if sub.Scopes != context.MISS {
			t.Errorf("expected helper_a scope to be MISS (%d), got %d", context.MISS, sub.Scopes)
		}

		if sub, ok := ctx.Subroutines["helper_b"]; !ok {
			t.Errorf("helper_b subroutine not found in context")
		} else if sub.Scopes != context.MISS {
			t.Errorf("expected helper_b scope to be MISS (%d), got %d", context.MISS, sub.Scopes)
		}
	})

	t.Run("annotation takes priority over inferred scope", func(t *testing.T) {
		// recv_helper has @scope: recv annotation but is called from vcl_miss
		// The annotation should take priority
		input := `
// @scope: recv
sub recv_helper {
  set req.http.X-Test = "value";
}

sub vcl_miss {
  #FASTLY MISS
  call recv_helper;
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatalf("unexpected parser error: %s", err)
		}

		l := New(testConfig)
		ctx := context.New()
		l.lint(vcl, ctx)

		// Should have no errors - annotation restricts scope to RECV
		for _, e := range l.Errors {
			if e.Severity == ERROR {
				t.Errorf("unexpected error: %s", e.Message)
			}
		}

		// Assert the scope is from annotation (RECV), not inferred (MISS)
		if sub, ok := ctx.Subroutines["recv_helper"]; !ok {
			t.Errorf("recv_helper subroutine not found in context")
		} else if sub.Scopes != context.RECV {
			t.Errorf("expected recv_helper scope to be RECV (%d) from annotation, got %d", context.RECV, sub.Scopes)
		}
	})

	t.Run("subroutine not called has unknown scope warning", func(t *testing.T) {
		// orphan_sub is not called from anywhere
		// Should get "Cannot recognize subroutine call scope" warning
		input := `
sub orphan_sub {
  set req.http.X-Test = "value";
}

sub vcl_recv {
  #FASTLY RECV
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatalf("unexpected parser error: %s", err)
		}

		l := New(testConfig)
		ctx := context.New()
		l.lint(vcl, ctx)

		// Should have a warning about unrecognized scope
		hasWarning := false
		for _, e := range l.Errors {
			if e.Severity == WARNING && e.Rule == UNRECOGNIZE_CALL_SCOPE {
				hasWarning = true
				break
			}
		}
		if !hasWarning {
			t.Errorf("expected warning about unrecognized scope for orphan_sub")
		}

		// Assert the orphan subroutine has no inferred scope (defaults to 0 before linting)
		if sub, ok := ctx.Subroutines["orphan_sub"]; !ok {
			t.Errorf("orphan_sub subroutine not found in context")
		} else if sub.Scopes != 0 {
			t.Errorf("expected orphan_sub scope to be 0 (unset), got %d", sub.Scopes)
		}
	})

	t.Run("infers scope with calls inside if statement", func(t *testing.T) {
		// to_origin is called inside an if block in vcl_miss
		input := `
sub to_origin {
  set bereq.http.CDN = "Fastly";
}

sub vcl_miss {
  #FASTLY MISS
  if (req.url ~ "^/api") {
    call to_origin;
  }
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatalf("unexpected parser error: %s", err)
		}

		l := New(testConfig)
		ctx := context.New()
		l.lint(vcl, ctx)

		// Should have no errors - call inside if block is detected
		for _, e := range l.Errors {
			if e.Severity == ERROR {
				t.Errorf("unexpected error: %s", e.Message)
			}
		}

		// Assert scope is inferred from vcl_miss
		if sub, ok := ctx.Subroutines["to_origin"]; !ok {
			t.Errorf("to_origin subroutine not found in context")
		} else if sub.Scopes != context.MISS {
			t.Errorf("expected to_origin scope to be MISS (%d), got %d", context.MISS, sub.Scopes)
		}
	})

	t.Run("detects scope conflict with DELIVER-only variable in MISS context", func(t *testing.T) {
		// This subroutine uses resp.http.X which is only available in DELIVER/LOG
		// but is called from vcl_miss - should error
		input := `
sub check_response {
  set resp.http.X-Test = "value";
}

sub vcl_miss {
  #FASTLY MISS
  call check_response;
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatalf("unexpected parser error: %s", err)
		}

		l := New(testConfig)
		ctx := context.New()
		l.lint(vcl, ctx)

		// Should have an error about variable not available in scope
		hasError := false
		for _, e := range l.Errors {
			if e.Severity == ERROR {
				hasError = true
				break
			}
		}
		if !hasError {
			t.Errorf("expected error for DELIVER-only variable used in MISS scope")
		}

		// Assert scope was correctly inferred as MISS (even though it causes an error)
		if sub, ok := ctx.Subroutines["check_response"]; !ok {
			t.Errorf("check_response subroutine not found in context")
		} else if sub.Scopes != context.MISS {
			t.Errorf("expected check_response scope to be MISS (%d), got %d", context.MISS, sub.Scopes)
		}
	})
}

func TestBuildCallGraph(t *testing.T) {
	t.Run("builds graph with simple calls", func(t *testing.T) {
		input := `
sub helper {
  set req.http.X = "1";
}

sub vcl_recv {
  #FASTLY RECV
  call helper;
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatalf("unexpected parser error: %s", err)
		}

		graph := buildCallGraph(vcl.Statements)

		if len(graph["vcl_recv"]) != 1 {
			t.Errorf("expected vcl_recv to have 1 callee, got %d", len(graph["vcl_recv"]))
		}
		if graph["vcl_recv"][0] != "helper" {
			t.Errorf("expected vcl_recv to call helper, got %s", graph["vcl_recv"][0])
		}

		// Also verify scope inference works
		l := New(testConfig)
		ctx := context.New()
		l.lint(vcl, ctx)

		if sub, ok := ctx.Subroutines["helper"]; !ok {
			t.Errorf("helper subroutine not found in context")
		} else if sub.Scopes != context.RECV {
			t.Errorf("expected helper scope to be RECV (%d), got %d", context.RECV, sub.Scopes)
		}
	})

	t.Run("builds graph with nested calls in if statements", func(t *testing.T) {
		input := `
sub helper_a {
  set req.http.X = "A";
}

sub helper_b {
  set req.http.X = "B";
}

sub vcl_recv {
  #FASTLY RECV
  if (req.url ~ "^/a") {
    call helper_a;
  } else {
    call helper_b;
  }
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatalf("unexpected parser error: %s", err)
		}

		graph := buildCallGraph(vcl.Statements)

		if len(graph["vcl_recv"]) != 2 {
			t.Errorf("expected vcl_recv to have 2 callees, got %d", len(graph["vcl_recv"]))
		}

		// Also verify scope inference works for both helpers
		l := New(testConfig)
		ctx := context.New()
		l.lint(vcl, ctx)

		if sub, ok := ctx.Subroutines["helper_a"]; !ok {
			t.Errorf("helper_a subroutine not found in context")
		} else if sub.Scopes != context.RECV {
			t.Errorf("expected helper_a scope to be RECV (%d), got %d", context.RECV, sub.Scopes)
		}

		if sub, ok := ctx.Subroutines["helper_b"]; !ok {
			t.Errorf("helper_b subroutine not found in context")
		} else if sub.Scopes != context.RECV {
			t.Errorf("expected helper_b scope to be RECV (%d), got %d", context.RECV, sub.Scopes)
		}
	})

	t.Run("handles self-recursion without infinite loop", func(t *testing.T) {
		// recursive_sub calls itself - should not cause infinite loop
		input := `
sub recursive_sub {
  if (req.http.Stop == "true") {
    return;
  }
  call recursive_sub;
}

sub vcl_recv {
  #FASTLY RECV
  call recursive_sub;
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatalf("unexpected parser error: %s", err)
		}

		graph := buildCallGraph(vcl.Statements)

		// recursive_sub should call itself
		if len(graph["recursive_sub"]) != 1 {
			t.Errorf("expected recursive_sub to have 1 callee, got %d", len(graph["recursive_sub"]))
		}
		if graph["recursive_sub"][0] != "recursive_sub" {
			t.Errorf("expected recursive_sub to call itself, got %s", graph["recursive_sub"][0])
		}

		// Verify scope inference completes without hanging
		l := New(testConfig)
		ctx := context.New()
		l.lint(vcl, ctx)

		if sub, ok := ctx.Subroutines["recursive_sub"]; !ok {
			t.Errorf("recursive_sub subroutine not found in context")
		} else if sub.Scopes != context.RECV {
			t.Errorf("expected recursive_sub scope to be RECV (%d), got %d", context.RECV, sub.Scopes)
		}
	})

	t.Run("handles mutual recursion without infinite loop", func(t *testing.T) {
		// sub_a calls sub_b which calls sub_a - mutual recursion
		input := `
sub sub_a {
  set req.http.X = "A";
  if (req.http.Stop != "true") {
    call sub_b;
  }
}

sub sub_b {
  set req.http.X = "B";
  if (req.http.Stop != "true") {
    call sub_a;
  }
}

sub vcl_recv {
  #FASTLY RECV
  call sub_a;
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Fatalf("unexpected parser error: %s", err)
		}

		graph := buildCallGraph(vcl.Statements)

		// sub_a should call sub_b
		if len(graph["sub_a"]) != 1 || graph["sub_a"][0] != "sub_b" {
			t.Errorf("expected sub_a to call sub_b, got %v", graph["sub_a"])
		}
		// sub_b should call sub_a
		if len(graph["sub_b"]) != 1 || graph["sub_b"][0] != "sub_a" {
			t.Errorf("expected sub_b to call sub_a, got %v", graph["sub_b"])
		}

		// Verify scope inference completes without hanging
		l := New(testConfig)
		ctx := context.New()
		l.lint(vcl, ctx)

		// Both subs should have RECV scope propagated
		if sub, ok := ctx.Subroutines["sub_a"]; !ok {
			t.Errorf("sub_a subroutine not found in context")
		} else if sub.Scopes != context.RECV {
			t.Errorf("expected sub_a scope to be RECV (%d), got %d", context.RECV, sub.Scopes)
		}

		if sub, ok := ctx.Subroutines["sub_b"]; !ok {
			t.Errorf("sub_b subroutine not found in context")
		} else if sub.Scopes != context.RECV {
			t.Errorf("expected sub_b scope to be RECV (%d), got %d", context.RECV, sub.Scopes)
		}
	})
}
