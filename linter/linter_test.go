package linter

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
	"github.com/ysugimoto/falco/resolver"
	"github.com/ysugimoto/falco/snippets"
	"github.com/ysugimoto/falco/types"
)

var testConfig = &config.LinterConfig{
	EnforceSubroutineScopes: map[string][]string{
		"enforced_subroutine": {"pass", "miss"},

		// Keep backward compatibility for the changes https://github.com/ysugimoto/falco/issues/273
		"foo":                {"recv"},
		"bar":                {"recv"},
		"baz":                {"recv"},
		"example":            {"recv"},
		"returns_one":        {"recv"},
		"custom_sub":         {"recv"},
		"test_sub":           {"recv"},
		"hoisted_subroutine": {"recv"},
		"returns_true":       {"recv"},
		"get_bool":           {"recv"},
	},
	IgnoreSubroutines: []string{
		"ignored_subroutine",
	},
}

func assertNoError(t *testing.T, input string, opts ...context.Option) {
	vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("unexpected parser error: %s", err)
		t.FailNow()
	}

	l := New(testConfig)
	l.lint(vcl, context.New(opts...))
	if len(l.Errors) > 0 {
		t.Errorf("Lint error: %s", l.Errors)
	}
	if l.FatalError != nil {
		t.Errorf("Fatal error: %s", l.FatalError.Error)
	}
}

func assertError(t *testing.T, input string, opts ...context.Option) {
	vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("unexpected parser error: %s", err)
		t.FailNow()
	}

	l := New(testConfig)
	l.lint(vcl, context.New(opts...))
	if len(l.Errors) == 0 {
		t.Errorf("Expect one lint error but empty returned")
	}
	if l.FatalError != nil {
		t.Errorf("Fatal error: %s", l.FatalError.Error)
	}
}
func assertErrorWithSeverity(t *testing.T, input string, severity Severity, opts ...context.Option) {
	vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("unexpected parser error: %s", err)
		t.FailNow()
	}

	l := New(testConfig)
	l.lint(vcl, context.New(opts...))
	if len(l.Errors) == 0 {
		t.Errorf("Expect one lint error but empty returned")
	}
	le, ok := l.Errors[0].(*LintError)
	if !ok {
		t.Errorf("Failed type conversion of *LintError")
	}
	if le.Severity != severity {
		t.Errorf("Severity expects %s but got %s with: %s", severity, le.Severity, le)
	}
}

func TestLintStuff(t *testing.T) {

	tests := []struct {
		name        string
		annotations string
		shouldError bool
	}{
		{
			name:        "Functions can be reused in multiple vcl state functions",
			annotations: "//@deliver, log",
			shouldError: false,
		},
		{
			name:        "Functions can be reused in multiple vcl state functions with scope",
			annotations: "//@scope:deliver, log",
			shouldError: false,
		},
		{
			name:        "Errros when subroutines want variables they don't have access to",
			annotations: "//@recv, log",
			shouldError: true,
		},
		{
			name:        "Errros when subroutines want variables they don't have access to with scope annotation",
			annotations: "//@scope: recv, log",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := fmt.Sprintf(`
			%s
			sub example BOOL {
				log resp.http.bar;
			}

			sub vcl_log {
				#FASTLY log
				if (example()) {
					log "foo";
				}
			}

			sub vcl_deliver {
			#FASTLY deliver
				if (example()) {
					log "foo";
				}
			}
			`, tt.annotations)
			if tt.shouldError {
				assertError(t, input)
			} else {
				assertNoError(t, input)
			}
		})
	}
}

func TestUnusedAcls(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
acl foo {}
sub bar {
	if (client.ip ~ foo) {}
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}

		l := New(testConfig)
		l.Lint(vcl, context.New())
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})
	t.Run("raise unused error", func(t *testing.T) {
		input := `
acl foo {}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}

		l := New(testConfig)
		l.Lint(vcl, context.New())
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})

	t.Run("raise unused external error", func(t *testing.T) {
		input := ` sub foo{}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}
		ctx := context.New()
		ctx.AddAcl("foo", &types.Acl{})
		l := New(testConfig)
		l.Lint(vcl, ctx)
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})
}

func TestUnusedTables(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
table foo {}
sub bar {
	set req.http.Foo = table.lookup(foo, "bar");
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}

		l := New(testConfig)
		l.Lint(vcl, context.New())
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})
	t.Run("raise unused error", func(t *testing.T) {
		input := `
table foo {}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}

		l := New(testConfig)
		l.Lint(vcl, context.New())
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})

	t.Run("raise unused external error", func(t *testing.T) {
		input := ` sub foo{}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}
		ctx := context.New()
		ctx.AddTable("foo", &types.Table{})
		l := New(testConfig)
		l.Lint(vcl, ctx)
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})
}

func TestUnusedBackend(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
backend foo {}
sub vcl_recl {
	set req.backend = foo;
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}

		l := New(testConfig)
		l.Lint(vcl, context.New())
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})
	t.Run("raise unused error", func(t *testing.T) {
		input := `
backend foo {}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}

		l := New(testConfig)
		l.Lint(vcl, context.New())
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})

	t.Run("raise unused external error", func(t *testing.T) {
		input := ` sub foo{}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}
		ctx := context.New()
		ctx.AddBackend("foo", &types.Backend{})
		l := New(testConfig)
		l.Lint(vcl, ctx)
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})
}

func TestUnusedSubroutine(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {}
sub vcl_recl {
	call foo;
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}

		l := New(testConfig)
		l.Lint(vcl, context.New())
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})
	t.Run("raise unused error", func(t *testing.T) {
		input := `
sub foo {}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}

		l := New(testConfig)
		l.Lint(vcl, context.New())
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})
}

func TestUnusedVariable(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub vcl_recv {
	declare local var.bar STRING;
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}

		l := New(testConfig)
		l.Lint(vcl, context.New())
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})
	t.Run("raise unused error", func(t *testing.T) {
		input := `
sub vcl_recv {
	declare local var.bar STRING;
	set var.bar = "baz";
}
`
		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}

		l := New(testConfig)
		l.Lint(vcl, context.New())
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
		}
	})
}

// https://github.com/ysugimoto/falco/issues/39
func TestPassIssue39(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub vcl_fetch {
	#FASTLY fetch
    if (parse_time_delta(beresp.http.Edge-Control:cache-maxage) >= 0) {
      set beresp.ttl = parse_time_delta(beresp.http.Edge-Control:cache-maxage);
    }
    return(deliver);
}
`
		assertNoError(t, input)
	})
}

func TestSubroutineHoisting(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	call hoisted_subroutine;
	return(lookup);
}

sub hoisted_subroutine {
	set req.http.X-Subrountine-Hoisted = "yes";
}
`
		assertNoError(t, input)
	})
}

func TestLintProtectedHTTPHeaders(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{
			name:  "Proxy-Authenticate",
			value: "Basic realm=\"Access to the proxy site\"",
		},
		{
			name:  "Proxy-Authorization",
			value: "Basic foo",
		},
		{
			name:  "Proxy-Authorization",
			value: "Basic foo",
		},
		{
			name:  "Content-Length",
			value: "100",
		},
		{
			name:  "Content-Range",
			value: "bytes 200-100/12345",
		},
		{
			name:  "TE",
			value: "gzip",
		},
		{
			name:  "Trailer",
			value: "Expires",
		},
		{
			name:  "Transfer-Encoding",
			value: "gzip",
		},
		{
			name:  "Expect",
			value: "100-continue",
		},
		{
			name:  "Upgrade",
			value: "example/1",
		},
		{
			name:  "Fastly-FF",
			value: "qZarR/12OL0QOq4VyQPmqQ/CTp17AZv0d6cSG5nUSxU=!WDC!cache-wdc5548-WDC",
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s in set statement", tt.name), func(t *testing.T) {
			input := fmt.Sprintf(`
	  sub vcl_recv {
		  #FASTLY RECV
		  set req.http.%s = "%s";
	  }`, tt.name, tt.value)
			assertError(t, input)
		})
		t.Run(fmt.Sprintf("%s in add statement", tt.name), func(t *testing.T) {
			input := fmt.Sprintf(`
	  sub vcl_recv {
		  #FASTLY RECV
		  add req.http.%s = "%s";
	  }`, tt.name, tt.value)
			assertError(t, input)
		})
		t.Run(fmt.Sprintf("%s in unset statement", tt.name), func(t *testing.T) {
			input := fmt.Sprintf(`
	  sub vcl_recv {
		  #FASTLY RECV
		  unset req.http.%s;
	  }`, tt.name)
			assertError(t, input)
		})
		t.Run(fmt.Sprintf("%s in remove statement", tt.name), func(t *testing.T) {
			input := fmt.Sprintf(`
	  sub vcl_recv {
		  #FASTLY RECV
		  remove req.http.%s;
	  }`, tt.name)
			assertError(t, input)
		})
	}
}

// statement resolve tests

type mockResolver struct {
	dependency map[string]string
	main       string
}

func (m *mockResolver) MainVCL() (*resolver.VCL, error) {
	return &resolver.VCL{
		Name: "main.vcl",
		Data: m.main,
	}, nil
}

func (m *mockResolver) Resolve(stmt *ast.IncludeStatement) (*resolver.VCL, error) {
	if v, ok := m.dependency[stmt.Module.Value]; !ok {
		return nil, errors.New(stmt.Module.Value + " is not defined")
	} else {
		return &resolver.VCL{
			Name: stmt.Module.Value + ".vcl",
			Data: v,
		}, nil
	}
}

func (m *mockResolver) Name() string {
	return ""
}

func TestResolveRootIncludeStatement(t *testing.T) {
	mock := &mockResolver{
		dependency: map[string]string{
			"deps01": `
sub foo {
	set req.backend = httpbin_org;
}

sub bar {
	set req.http.Foo = "bar";
}
			`,
		},
	}
	input := `
backend httpbin_org {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "httpbin.org";
  .first_byte_timeout = 20s;
  .max_connections = 500;
  .between_bytes_timeout = 20s;
  .share_key = "xei5lohleex3Joh5ie5uy7du";
  .ssl = true;
  .ssl_sni_hostname = "httpbin.org";
  .ssl_cert_hostname = "httpbin.org";
  .ssl_check_cert = always;
  .min_tls_version = "1.2";
  .max_tls_version = "1.2";
}

include "deps01";

sub vcl_recv {
   #FASTLY RECV
   call foo;
}
		`
	assertNoError(t, input, context.WithResolver(mock))
}

func TestResolveNestedIncludeStatement(t *testing.T) {
	mock := &mockResolver{
		dependency: map[string]string{
			"deps01": `
include "deps02";
			`,
			"deps02": `
sub foo {
	set req.backend = httpbin_org;
}
			`,
		},
	}
	input := `
backend httpbin_org {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "httpbin.org";
  .first_byte_timeout = 20s;
  .max_connections = 500;
  .between_bytes_timeout = 20s;
  .share_key = "xei5lohleex3Joh5ie5uy7du";
  .ssl = true;
  .ssl_sni_hostname = "httpbin.org";
  .ssl_cert_hostname = "httpbin.org";
  .ssl_check_cert = always;
  .min_tls_version = "1.2";
  .max_tls_version = "1.2";
}

include "deps01";

sub vcl_recv {
   #FASTLY RECV
   call foo;
}
		`
	assertNoError(t, input, context.WithResolver(mock))
}

func TestResolveIncludeStateInIfStatement(t *testing.T) {
	mock := &mockResolver{
		dependency: map[string]string{
			"deps01": `
set req.http.Foo = "bar";
			`,
		},
	}
	input := `
sub vcl_recv {
   #FASTLY RECV
   if (req.http.Is-Some-Truthy) {
		include "deps01";
   }
}
		`
	assertNoError(t, input, context.WithResolver(mock))
}

func TestFastlyScopedSnippetInclusion(t *testing.T) {
	snippets := &snippets.Snippets{
		ScopedSnippets: map[string][]snippets.SnippetItem{
			"recv": {
				{
					Name: "recv_injection",
					Data: `set req.http.InjectedViaMacro = 1;`,
				},
			},
		},
	}
	input := `
sub vcl_recv {
   #FASTLY RECV

   return (pass);
}
`
	assertError(t, input, context.WithSnippets(snippets))
}

func TestFastlySnippetInclusion(t *testing.T) {
	snippets := &snippets.Snippets{
		IncludeSnippets: map[string]snippets.SnippetItem{
			"recv_injection": {
				Name: "recv_injection",
				Data: `set req.http.InjectedViaMacro = 1;`,
			},
		},
	}
	input := `
sub vcl_recv {
   #FASTLY RECV
   if (req.http.Some-Truthy) {
	  include "snippet::recv_injection";
   }
}
`
	assertError(t, input, context.WithSnippets(snippets))
}

func TestFastlyInfoH2FingerPrintCouldLint(t *testing.T) {
	input := `
sub vcl_recv {
   #FASTLY RECV
   set req.http.H2-Fingerprint = fastly_info.h2.fingerprint;
}`
	assertNoError(t, input)
}

func TestIgnoreErrorNextLine(t *testing.T) {
	input := `
sub vcl_recv {
   #FASTLY RECV
   # falco-ignore-next-line
   set req.http.H2-Fingerprint = fastly_info.h2.undefined; // undefined but ignore
}`
	assertNoError(t, input)
}

func TestIgnoreErrorNextLineWithRuleSpecified(t *testing.T) {
	input := `
sub vcl_recv {
   #FASTLY RECV
   # function/arguments is ignored, but there is also a function/argument-type error
   # falco-ignore-next-line function/arguments
   set req.http.foo = std.itoa(req.http.bar) + std.itoa(0, 1, 2);
}`
	assertError(t, input)
}

func TestIgnoreErrorNextLineWithMultipleRulesSpecified(t *testing.T) {
	input := `
sub vcl_recv {
   #FASTLY RECV
   # falco-ignore-next-line function/arguments, function/argument-type
   set req.http.foo = std.itoa(req.http.bar) + std.itoa(0, 1, 2);
}`
	assertNoError(t, input)
}

func TestIgnoreErrorNextLineOnly(t *testing.T) {
	input := `
sub vcl_recv {
   #FASTLY RECV
   # falco-ignore-next-line
   set req.http.H2-Fingerprint = fastly_info.h2.undefined; // undefined but ignore
   set req.http.H2-Fingerprint = fastly_info.h2.undefined; // raise an error
}`
	assertError(t, input)
}

func TestIgnoreErrorThisLine(t *testing.T) {
	input := `
sub vcl_recv {
   #FASTLY RECV
   set req.http.H2-Fingerprint = fastly_info.h2.undefined; // falco-ignore
}`
	assertNoError(t, input)
}

func TestIgnoreErrorThisLineWithRuleSpecified(t *testing.T) {
	input := `
sub vcl_recv {
   #FASTLY RECV
   # function/arguments is ignored, but there is also a function/argument-type error
   set req.http.foo = std.itoa(req.http.bar) + std.itoa(0, 1, 2); # falco-ignore function/arguments
}`
	assertError(t, input)
}

func TestIgnoreErrorThisLineWithMultipleRulesSpecified(t *testing.T) {
	input := `
sub vcl_recv {
   #FASTLY RECV
   set req.http.foo = std.itoa(req.http.bar) + std.itoa(0, 1, 2); # falco-ignore function/arguments, function/argument-type
}`
	assertNoError(t, input)
}

func TestIgnoreErrorStartEnd(t *testing.T) {
	input := `
sub vcl_recv {
	// falco-ignore-start
   #FASTLY RECV
   set req.http.H2-Fingerprint = fastly_info.h2.undefined;
	// falco-ignore-end
   set req.http.H2-Fingerprint = fastly_info.h2.fingerprint;
}`
	assertNoError(t, input)
}

func TestIgnoreErrorStartEndWithRuleSpecified(t *testing.T) {
	input := `
sub vcl_recv {
   # falco-ignore-start function/arguments
   #FASTLY RECV
   # function/arguments is ignored, but there is also a function/argument-type error
   set req.http.foo = std.itoa(req.http.bar) + std.itoa(0, 1, 2);
   # falco-ignore-end function/arguments
}`
	assertError(t, input)
}

func TestIgnoreErrorStartEndWithMultipleRulesSpecified(t *testing.T) {
	input := `
sub vcl_recv {
   # falco-ignore-start function/arguments, function/argument-type
   #FASTLY RECV
   set req.http.foo = std.itoa(req.http.bar) + std.itoa(0, 1, 2);
   # falco-ignore-end function/arguments, function/argument-type
}`
	assertNoError(t, input)
}

func TestIgnoreErrorStartEndRangeOnly(t *testing.T) {
	input := `
sub vcl_recv {
	// falco-ignore-start
   #FASTLY RECV
   set req.http.H2-Fingerprint = fastly_info.h2.undefined;
	// falco-ignore-end
   set req.http.H2-Fingerprint = fastly_info.h2.undefined;
}`
	assertError(t, input)
}

func TestIgnoreErrorStartEndRangeOnlyWithRuleSpecified(t *testing.T) {
	input := `
sub vcl_recv {
   # falco-ignore-start function/arguments, function/argument-type
   #FASTLY RECV
   set req.http.foo = std.itoa(req.http.bar) + std.itoa(0, 1, 2);
   # falco-ignore-end function/arguments
   set req.http.foo = std.itoa(req.http.bar);
}`
	assertNoError(t, input)
}

func TestIgnoreErrorStartEndRangeOnly_EndWithNoRulesSpecifiedUnignoresAllRules(t *testing.T) {
	input := `
sub vcl_recv {
   # falco-ignore-start function/arguments
   #FASTLY RECV
   set req.http.foo = std.itoa(0, 1, 2);
   # falco-ignore-start function/argument-type
   set req.http.foo = std.itoa(req.http.bar) + std.itoa(0, 1, 2);
   # falco-ignore-end
   set req.http.foo = std.itoa(0, 1, 2);
}`
	assertError(t, input)
}

func TestIgnoreErrorStartEndWholeDeclaration(t *testing.T) {
	input := `
// falco-ignore-start
sub vcl_recv {
   #FASTLY RECV
   set req.http.H2-Fingerprint = fastly_info.h2.undefined;
   set req.http.H2-Fingerprint = fastly_info.h2.fingerprint;
}`
	assertNoError(t, input)
}

func TestEnforcedSubroutineScopes(t *testing.T) {
	t.Run("Pass on enforce scope subroutine", func(t *testing.T) {
		input := `
sub enforced_subroutine {
	set bereq.method = "POST";
}
`
		assertNoError(t, input)
	})
}

func TestIgnoredSubroutnes(t *testing.T) {
	t.Run("ignore subroutine linting from config", func(t *testing.T) {
		input := `
sub ignored_subroutine {
	set bereq.method = 1;
}
`
		assertNoError(t, input)
	})
}
