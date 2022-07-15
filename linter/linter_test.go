package linter

import (
	"testing"

	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

func assertNoError(t *testing.T, input string) {
	vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("unexpected parser error: %s", err)
		t.FailNow()
	}

	l := New()
	l.lint(vcl, context.New())
	if len(l.Errors) > 0 {
		t.Errorf("Lint error: %s", l.Errors)
	}
}

func assertError(t *testing.T, input string) {
	vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("unexpected parser error: %s", err)
		t.FailNow()
	}

	l := New()
	l.lint(vcl, context.New())
	if len(l.Errors) == 0 {
		t.Errorf("Expect one lint error but empty returned")
	}
}
func assertErrorWithSeverity(t *testing.T, input string, severity Severity) {
	vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Errorf("unexpected parser error: %s", err)
		t.FailNow()
	}

	l := New()
	l.lint(vcl, context.New())
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

func TestLintAclStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
acl example {
  !"192.168.0.1"/32;
}`
		assertNoError(t, input)
	})

	t.Run("invalid acl name", func(t *testing.T) {
		input := `
acl invalid-acl-name {
  !"192.168.0.1"/32;
}`
		assertError(t, input)
	})

	t.Run("duplicated error", func(t *testing.T) {
		input := `
acl example {
  !"192.168.0.1"/32;
}

acl example {
  "192.168.0.2"/32;
}
`
		assertError(t, input)
	})
}

func TestLintBackendStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
backend foo {
  .host = "example.com";

  .probe = {
    .request = "GET / HTTP/1.1";
  }
}`
		assertNoError(t, input)
	})

	t.Run("invalid backend name", func(t *testing.T) {
		input := `
backend foo-bar {
  .host = "example.com";
}`
		assertError(t, input)
	})

	t.Run("invalid type", func(t *testing.T) {
		input := `
backend foo-bar {
  .host = 1s;
}`
		assertError(t, input)
	})

	t.Run("duplicate backend", func(t *testing.T) {
		input := `
backend foo {
  .host = "example.com";
}

backend foo {
  .host = "example.com";
}`
		assertError(t, input)
	})

	t.Run("probe must be an object", func(t *testing.T) {
		input := `
backend foo {
  .host = "example.com";
  .probe = "probe";
}
`
		assertError(t, input)
	})

	t.Run("Probe is configured correctly", func(t *testing.T) {
		input := `
backend foo {
  .host = "example.com";

  .probe = {
    .request = "GET / HTTP/1.1";
	.threshold = 1;
	.initial = 5;
  }
}`
		assertNoError(t, input)
	})

	t.Run("Probe is configured in such a way that the backend will start as unhealthy", func(t *testing.T) {
		input := `
backend foo {
  .host = "example.com";

  .probe = {
    .request = "GET / HTTP/1.1";
	.threshold = 5;
	.initial = 1;
  }
}`
		assertError(t, input)
	})
}

func TestLintTableStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
table example {
	"foo": "bar",
}`
		assertNoError(t, input)
	})

	t.Run("invalid table name", func(t *testing.T) {
		input := `
table example-table {
	"foo": "bar",
}`
		assertError(t, input)
	})

	t.Run("invalid table value type", func(t *testing.T) {
		input := `
table example INTEGER {
	"foo": 1s,
}`
		assertError(t, input)
	})

	t.Run("dulicated definition", func(t *testing.T) {
		input := `
table example INTEGER {
	"foo": 10,
}
table example  {
	"foo": "bar",
}`
		assertError(t, input)
	})
}

func TestLintDirectorStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar client {
	.quorum  = 50%;
	{ .backend = foo; .weight = 1; }
}`
		assertNoError(t, input)
	})

	t.Run("invalid director name", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar-baz client {
	.quorum  = 50%;
	{ .backend = foo; .weight = 1; }
}`
		assertError(t, input)
	})

	t.Run("unexpected director property", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar fallback {
	{ .backend = foo; .weight = 1; }
}`
		assertError(t, input)
	})

	t.Run("invalid director type", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar testing {
	{ .backend = foo; }
}`
		assertError(t, input)
	})

	t.Run("duplicate director declared", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar fallback {
	{ .backend = foo; }
}

director bar fallback {
	{ .backend = foo; }
}`
		assertError(t, input)
	})

	t.Run("required backend property is not declared", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar client {
	{ .backend = foo; }
}`

		assertError(t, input)
	})

	t.Run("backend is not declared in director", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar client {
	.quorum = 50%;
}`

		assertError(t, input)
	})

	t.Run("undefined backend is specified", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar client {
	.quorum = 50%;
	{ .backend = baz; .weight = 1; }
}`

		assertError(t, input)
	})
}

func TestLintSubroutineStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub example {
	set req.http.Host = "example.com";
}`
		assertNoError(t, input)
	})

	t.Run("pass with Fastly reserved subroutine boilerplate comment", func(t *testing.T) {
		input := `
sub vcl_recv {
	# FASTLY recv
	set req.http.Host = "example.com";
}`
		assertNoError(t, input)

		input = `
sub vcl_log {
	# FASTLY log
}`
		assertNoError(t, input)
	})

	t.Run("invalid subroutine name", func(t *testing.T) {
		input := `
sub vcl-recv {
	set req.http.Host = "example.com";
}`
		assertError(t, input)
	})

	t.Run("duplicate subroutine declared", func(t *testing.T) {
		input := `
sub foo {
	set req.http.Host = "example.com";
}

sub foo {
	set req.http.Host = "httpbin.org";
}`
		assertError(t, input)
	})

	t.Run("Fastly reserved subroutine needs boilerplate comment", func(t *testing.T) {
		input := `
sub vcl_recv {
	set req.http.Host = "example.com";
}`
		assertError(t, input)
	})

	t.Run("Fastly reserved subroutine cannot have a return type", func(t *testing.T) {
		input := `
sub vcl_recv BOOL {
	set req.http.Host = "example.com";
	return true;
}`
		assertError(t, input)
	})
}

func TestLintDeclareStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
acl foo {}
backend bar {}
sub baz {
	declare local var.item1 STRING;
	declare local var.item2 INTEGER;
	declare local var.item3 FLOAT;
	declare local var.item4 IP;
	declare local var.item5 ID;
	declare local var.item6 ACL;
	declare local var.item7 BACKEND;

	set var.item1 = "1";
	set var.item2 = 1;
	set var.item3 = 1.0;
	set var.item4 = std.ip("192.168.0.1", "192.168.0.2");
	set var.item5 = always;
	set var.item6 = foo;
	set var.item7 = bar;

}`
		assertNoError(t, input)
	})

	t.Run("variable name does not start with var.", func(t *testing.T) {
		input := `
sub foo {
	declare local some.item1 STRING;
}`
		assertError(t, input)
	})

	t.Run("duplicate variable is declared", func(t *testing.T) {
		input := `
sub foo {
	declare local var.item1 STRING;
	declare local var.item1 STRING;

	set var.item1 = "bar";
}`
		assertError(t, input)
	})
}

func TestLintSetStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	set req.http.Host = "example.com";
}`

		assertNoError(t, input)
	})

	t.Run("pass with expression", func(t *testing.T) {
		input := `
sub foo {
	set req.http.Host = "example" req.http.User-Agent ",com";
}`

		assertNoError(t, input)
	})

	t.Run("pass with deep fastly variable", func(t *testing.T) {
		input := `
sub foo {
	set req.http.Host = client.geo.city.utf8;
}`

		assertNoError(t, input)
	})

	t.Run("invalid variable name", func(t *testing.T) {
		input := `
sub foo {
	set foo_bar_baz = "example.com";
}`

		assertError(t, input)
	})

	t.Run("undefined variable", func(t *testing.T) {
		input := `
sub foo {
	set req.unknwon.Host = "example.com";
}`

		assertError(t, input)
	})

	t.Run("invalid type", func(t *testing.T) {
		input := `
sub foo {
	set req.http.Host = 10;
}`

		assertError(t, input)
	})
}

func TestLintUnsetStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	unset req.http.Host;
}`

		assertNoError(t, input)
	})

	t.Run("invalid variable name", func(t *testing.T) {
		input := `
sub foo {
	unset foo_bar_baz;
}`

		assertError(t, input)
	})

	t.Run("undefined variable", func(t *testing.T) {
		input := `
sub foo {
	unset req.unknwon.Host;
}`

		assertError(t, input)
	})

	t.Run("could not unset variable", func(t *testing.T) {
		input := `
sub foo {
	unset req.backend;
}`

		assertError(t, input)
	})
}

func TestLintAddStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	add req.http.Host = "example.com";
}`

		assertNoError(t, input)
	})

	t.Run("pass with expression", func(t *testing.T) {
		input := `
sub foo {
	add req.http.Host = "example" req.http.User-Agent ",com";
}`

		assertNoError(t, input)
	})

	t.Run("invalid variable name", func(t *testing.T) {
		input := `
sub foo {
	add foo_bar_baz = "example.com";
}`

		assertError(t, input)
	})

	t.Run("undefined variable", func(t *testing.T) {
		input := `
sub foo {
	add req.unknwon.Host = "example.com";
}`

		assertError(t, input)
	})

	t.Run("invalid type", func(t *testing.T) {
		input := `
sub foo {
	add req.http.Host = 10;
}`

		assertError(t, input)
	})

	t.Run("only can use for HTTP headers", func(t *testing.T) {
		input := `
sub foo {
	declare local var.FOO STRING;
	add var.FOO = "bar";
}`

		assertError(t, input)
	})
}

func TestLintCallStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	set req.http.Host = "example.com";
}

sub bar {
	call foo;
}
`

		assertNoError(t, input)
	})

	t.Run("undefined call target subroutine", func(t *testing.T) {
		input := `
sub other {
	call foo;
}`

		assertError(t, input)
	})
}

func TestLintErrorStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	error 602;
}
`
		assertNoError(t, input)
	})

	t.Run("warning when error code uses greater than 699", func(t *testing.T) {
		input := `
sub foo {
	error 700;
}
`
		assertError(t, input)
	})

	t.Run("invalid subroutine phase", func(t *testing.T) {
		input := `
// @log
sub foo {
	error 602;
}
`
		assertError(t, input)
	})
}

func TestLintIfStatement(t *testing.T) {
	t.Run("pass: single if", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host) {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("pass: multiple condition expression", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host && req.http.User-Agent ~ "foo") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("pass: if-else", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host) {
		restart;
	} else {
		error 601;
	}
}`
		assertNoError(t, input)
	})

	t.Run("pass: if-elseif-else", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host) {
		restart;
	} else if (req.http.X-Forwarded-For) {
		error 602;
	} else {
		error 601;
	}
}`
		assertNoError(t, input)
	})

	t.Run("pass: use re.group.N outside if consequence", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;
	set var.S = "foo.bar.baz.example.com";
	if (var.S ~ "foo\.(^[.]+)\.baz") {
		restart;
	}
	set var.S = re.group.1;
}`
		assertNoError(t, input)
	})

	t.Run("can use re.group.N if condition has regex operator", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;
	set var.S = "foo.bar.baz.example.com";
	if (var.S ~ "foo\.(^[.]+)\.baz") {
		set var.S = re.group.1;
	}
}`
		assertNoError(t, input)
	})

	t.Run("re.group.N may override on second time", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;
	set var.S = "foo.bar.baz.example.com";
	if (var.S ~ "foo\.(^[.]+)\.baz") {
		if (var.S ~ "(^[.]+)\.bar") {
			restart;
		}
		restart;
	}
	set var.S = re.group.1;
}`
		assertErrorWithSeverity(t, input, INFO)
	})

	t.Run("condition type is not expected", func(t *testing.T) {
		input := `
sub foo {
	declare local var.I INTEGER;
	set var.I = 10;
	if (var.I) {
		restart;
	}
}`
		assertError(t, input)
	})

	t.Run("condition type is STRING but defined as string literal", func(t *testing.T) {
		input := `
sub foo {
	if ("foobar") {
		restart;
	}
}`
		assertError(t, input)
	})
}

func TestLintBangPrefixExpression(t *testing.T) {
	t.Run("pass: use with variable identity", func(t *testing.T) {
		input := `
sub foo {
	declare local var.Foo BOOL;
	set var.Foo = true;

	if (!var.Foo) {
		restart;
	}
}`
		assertNoError(t, input)

	})
	t.Run("pass: use with boolean literal", func(t *testing.T) {
		input := `
sub foo {
	if (!true) {
		restart;
	}
}`
		assertNoError(t, input)

	})

	t.Run("could not use in string literal", func(t *testing.T) {
		input := `
sub foo {
	if (!"bar") {
		restart;
	}
}`
		assertError(t, input)

	})

	t.Run("could not use on other statement", func(t *testing.T) {
		input := `
sub foo {
	declare local var.Foo BOOL;
	set var.Foo = !true;
}`
		assertError(t, input)
	})
}

func TestLintEqualOperator(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host == "example.com") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("cannot use in other statement", func(t *testing.T) {
		input := `
sub foo {
	declare local var.BoolItem BOOL;
	set var.BoolItem = req.http.Host == "example.com";
}`
		assertError(t, input)
	})

	t.Run("cannot compare for different type", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host == 10) {
		restart;
	}
}`
		assertError(t, input)
	})
}

func TestLintNotEqualOperator(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host != "example.com") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("cannot use in other statement", func(t *testing.T) {
		input := `
sub foo {
	declare local var.BoolItem BOOL;
	set var.BoolItem = req.http.Host != "example.com";
}`
		assertError(t, input)
	})

	t.Run("cannot compare for different type", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host != 10) {
		restart;
	}
}`
		assertError(t, input)
	})
}

func TestLintGreaterThanOperator(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	declare local var.I INTEGER;
	set var.I = 100;
	if (var.I > 10) {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("cannot use in other statement", func(t *testing.T) {
		input := `
sub foo {
	declare local var.BoolItem BOOL;
	set var.BoolItem = req.http.Host > "example.com";
}`
		assertError(t, input)
	})

	t.Run("cannot compare for different type", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host > 10) {
		restart;
	}
}`
		assertError(t, input)
	})

	t.Run("cannot compare INTEGER vs FLOAT", func(t *testing.T) {
		input := `
sub foo {
	declare local var.I INTEGER;
	set var.I = 100;
	if (var.I > 10.0) {
		restart;
	}
}`
		assertError(t, input)
	})
}

func TestLintGreaterThanEqualOperator(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	declare local var.I INTEGER;
	set var.I = 100;
	if (var.I >= 10) {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("cannot use in other statement", func(t *testing.T) {
		input := `
sub foo {
	declare local var.BoolItem BOOL;
	set var.BoolItem = req.http.Host >= "example.com";
}`
		assertError(t, input)
	})

	t.Run("cannot compare for different type", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host >= 10) {
		restart;
	}
}`
		assertError(t, input)
	})

	t.Run("cannot compare INTEGER vs FLOAT", func(t *testing.T) {
		input := `
sub foo {
	declare local var.I INTEGER;
	set var.I = 100;
	if (var.I >= 10.0) {
		restart;
	}
}`
		assertError(t, input)

	})
}

func TestLintLessThanOperator(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	declare local var.I INTEGER;
	set var.I = 100;
	if (var.I < 10) {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("cannot use in other statement", func(t *testing.T) {
		input := `
sub foo {
	declare local var.BoolItem BOOL;
	set var.BoolItem = req.http.Host < "example.com";
}`
		assertError(t, input)
	})

	t.Run("cannot compare for different type", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host < 10) {
		restart;
	}
}`
		assertError(t, input)
	})

	t.Run("cannot compare INTEGER vs FLOAT", func(t *testing.T) {
		input := `
sub foo {
	declare local var.I INTEGER;
	set var.I = 100;
	if (var.I < 10.0) {
		restart;
	}
}`
		assertError(t, input)
	})
}

func TestLintLessThanEqualOperator(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	declare local var.I INTEGER;
	set var.I = 100;
	if (var.I <= 10) {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("cannot use in other statement", func(t *testing.T) {
		input := `
sub foo {
	declare local var.BoolItem BOOL;
	set var.BoolItem = req.http.Host <= "example.com";
}`
		assertError(t, input)
	})

	t.Run("cannot compare for different type", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host <= 10) {
		restart;
	}
}`
		assertError(t, input)
	})

	t.Run("cannot compare INTEGER vs FLOAT", func(t *testing.T) {
		input := `
sub foo {
	declare local var.I INTEGER;
	set var.I = 100;
	if (var.I <= 10.0) {
		restart;
	}
}`
		assertError(t, input)

	})
}

func TestLintRegexOperator(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host ~ "example") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("pass with acl", func(t *testing.T) {
		input := `
acl internal {
	"10.0.0.10";
}

sub foo {
	if (req.http.Host ~ internal) {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("cannot use in other statement", func(t *testing.T) {
		input := `
sub foo {
	declare local var.BoolItem BOOL;
	set var.BoolItem = req.http.Host ~ "example.com";
}`
		assertError(t, input)
	})

	t.Run("cannot compare for different type", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host ~ 10) {
		restart;
	}
}`
		assertError(t, input)
	})
}

func TestLintRegexNotOperator(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host !~ "example") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("pass with acl", func(t *testing.T) {
		input := `
acl internal {
	"10.0.0.10";
}

sub foo {
	if (req.http.Host !~ internal) {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("cannot use in other statement", func(t *testing.T) {
		input := `
sub foo {
	declare local var.BoolItem BOOL;
	set var.BoolItem = req.http.Host !~ "example.com";
}`
		assertError(t, input)
	})

	t.Run("cannot compare for different type", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host !~ 10) {
		restart;
	}
}`
		assertError(t, input)
	})
}

func TestLintPlusOperator(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;
	set var.S = "foo" "bar" + "baz";
}`
		assertNoError(t, input)
	})

	t.Run("raise warning concatenation without string type", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;
	declare local var.I INTEGER;

	set var.I = 10;
	set var.S = "foo" "bar" + var.I;
}`
		// error, but warning
		assertErrorWithSeverity(t, input, INFO)
	})
}

func TestLintIfExpression(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;

	set var.S = if(req.http.Host == "example.com" && req.http.Host ~ "example", "foo", "bar");
}`
		assertNoError(t, input)
	})

	t.Run("could not use literal in expression condition", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;
	declare local var.I INTEGER;

	set var.I = if(10 > 10, var.I, var.S);
}`
		assertError(t, input)
	})

	t.Run("raise warning when if expression returns different type", func(t *testing.T) {
		input := `
sub foo {
	declare local var.I INTEGER;

	set var.I = if(req.http.Host ~ "example", "1", var.I);
}`
		assertErrorWithSeverity(t, input, WARNING)

	})
}

func TestLintFunctionCallExpression(t *testing.T) {
	t.Run("pass with no argument", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;

	set var.S = uuid.version4();
}`
		assertNoError(t, input)
	})

	t.Run("pass with exact argument", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;

	set var.S = substr("foobarbaz", 1, 2);
}`
		assertNoError(t, input)
	})

	t.Run("pass with optional argument", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;

	set var.S = substr("foobarbaz", 1);
}`
		assertNoError(t, input)
	})

	t.Run("pass with user defined sub", func(t *testing.T) {
		input := `
sub returns_one INTEGER {
	return 1;
}

sub returns_true BOOL {
	return returns_one() == 1;
}`
		assertNoError(t, input)
	})

	t.Run("function not found", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;

	set var.S = undefined_function("foobarbaz");
}`
		assertError(t, input)
	})

	t.Run("error when argument count mismatched", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;

	set var.S = substr("foobarbaz");
}`
		assertError(t, input)
	})

	t.Run("error when argument type mismatched", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;

	set var.S = substr("foobarbaz", "bar");
}`
		assertError(t, input)
	})

	t.Run("fuzzy type check for TIME type argument", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;
	declare local var.T TIME;
	set var.S = "Mon, 02 Jan 2006 22:04:05 GMT";

	set var.T = std.time(var.S, "Mon Jan 2 22:04:05 2006");
}`
		assertNoError(t, input)
	})
}

func TestReturnStatement(t *testing.T) {
	t.Run("pass: without argument", func(t *testing.T) {
		input := `
sub foo {
	return;
}`
		assertNoError(t, input)
	})

	t.Run("pass: with argument", func(t *testing.T) {
		input := `
sub vcl_recv {
	#Fastly recv
	return (pass);
}`
		assertNoError(t, input)
	})

	t.Run("sub: return correct type", func(t *testing.T) {
		input := `
sub custom_sub INTEGER {
	#Fastly recv
	return 1;
}`
		assertNoError(t, input)
	})

	t.Run("sub: return empty statement", func(t *testing.T) {
		input := `
sub custom_sub INTEGER {
	return;
}`
		assertError(t, input)
	})

	t.Run("sub: return wrong type", func(t *testing.T) {
		input := `
sub custom_sub INTEGER {
	return (req.http.foo);
}`
		assertError(t, input)
	})

	t.Run("sub: return action", func(t *testing.T) {
		input := `
sub custom_sub INTEGER {
	return (pass);
}`
		assertError(t, input)
	})

	t.Run("sub: return value as action", func(t *testing.T) {
		input := `
sub custom_sub INTEGER {
	return (1);
}`
		assertError(t, input)
	})

	t.Run("sub: return local value", func(t *testing.T) {
		input := `
sub custom_sub INTEGER {
	declare local var.tmp INTEGER;
	set var.tmp = 10;
	return var.tmp;
}`
		assertNoError(t, input)
	})

	t.Run("sub: return value contains operations", func(t *testing.T) {
		input := `
sub get_str STRING {
	declare local var.tmp STRING;
	set var.tmp = "foo";
	return var.tmp "bar";
}`
		assertError(t, input)
	})

	t.Run("sub: return value contains jibber", func(t *testing.T) {
		input := `
sub get_str STRING {
	declare local var.tmp STRING;
	set var.tmp = "foo";
	return +-var.tmp;
}`
		assertError(t, input)
	})

	t.Run("sub: bool return value is allowed to have operations", func(t *testing.T) {
		input := `
sub get_bool BOOL {
	declare local var.tmp STRING;
	set var.tmp = "foo";
	return std.strlen(var.tmp) > 5;
}`
		assertNoError(t, input)
	})

}

func TestBlockSyntaxInsideBlockStatement(t *testing.T) {
	input := `
sub vcl_recv {
	#Fastly recv
	{
		log "vcl_recv";
	}
}`
	assertNoError(t, input)
}

func TestBlockSyntaxInsideBlockStatementmultiply(t *testing.T) {
	input := `
sub vcl_recv {
	#Fastly recv
	{
		{
			log "vcl_recv";
		}
	}
}`
	assertNoError(t, input)
}

func TestRegexExpressionIsInvalid(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub vcl_recv {
	#Fastly recv
	if (req.url ~ "^/([^\?]*)?(\?.*)?$") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("error: invalid regex", func(t *testing.T) {
		input := `
sub vcl_recv {
	#Fastly recv
	if (req.url ~ "^/([^\?]*)?(\?.*?$") {
		restart;
	}
}`
		assertError(t, input)
	})
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

		l := New()
		l.Lint(vcl, context.New(), true)
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

		l := New()
		l.Lint(vcl, context.New(), true)
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

		l := New()
		l.Lint(vcl, context.New(), true)
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

		l := New()
		l.Lint(vcl, context.New(), true)
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

		l := New()
		l.Lint(vcl, context.New(), true)
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

		l := New()
		l.Lint(vcl, context.New(), true)
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

		l := New()
		l.Lint(vcl, context.New(), true)
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

		l := New()
		l.Lint(vcl, context.New(), true)
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

		l := New()
		l.Lint(vcl, context.New(), true)
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

		l := New()
		l.Lint(vcl, context.New(), true)
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
	### FASTLY fetch
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
	### FASTLY recv
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

func TestLintPenaltyboxStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
penaltybox ip_pb {}
`
		assertNoError(t, input)
	})

	t.Run("pass with comments", func(t *testing.T) {
		input := `
penaltybox ip_pb {
	// This is a comment
}
`
		assertNoError(t, input)
	})

	t.Run("invalid penaltybox name", func(t *testing.T) {
		input := `
penaltybox vcl-recv {}
	`
		assertError(t, input)
	})

	t.Run("duplicate penaltybox declared", func(t *testing.T) {
		input := `
penaltybox ip_pb {}
penaltybox ip_pb {}
	`
		assertError(t, input)
	})

	t.Run("penaltybox block is not empty", func(t *testing.T) {
		input := `
penaltybox ip_pb {
	set var.bar = "baz";
}
`
		assertError(t, input)
	})

	t.Run("penaltybox variable should be pass if it is defined", func(t *testing.T) {
		input := `
penaltybox ip_pb {}
ratecounter counter_60 {}

sub test_sub{
	declare local var.ratelimit_exceeded BOOL;
	set var.ratelimit_exceeded = ratelimit.check_rate(
		digest.hash_sha256("123"),
		counter_60,
		1,
		60,
		135,
		ip_pb,
		2m);
}
`
		assertNoError(t, input)
	})

	t.Run("penaltybox variable should be defined", func(t *testing.T) {
		input := `
ratecounter counter_60 {}

sub test_sub{
	declare local var.ratelimit_exceeded BOOL;
	set var.ratelimit_exceeded = ratelimit.check_rate(
		digest.hash_sha256("123"),
		counter_60,
		1,
		60,
		135,
		ip_pb,
		2m);
}
`
		assertError(t, input)
	})
}

func TestLintRatecounterStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
ratecounter req_counter {}
`
		assertNoError(t, input)
	})

	t.Run("pass with comments", func(t *testing.T) {
		input := `
ratecounter req_counter {
	// This is a comment
}
`
		assertNoError(t, input)
	})

	t.Run("invalid ratecounter name", func(t *testing.T) {
		input := `
ratecounter vcl-recv {}
	`
		assertError(t, input)
	})

	t.Run("duplicate ratecounter declared", func(t *testing.T) {
		input := `
ratecounter req_counter {}
ratecounter req_counter {}
	`
		assertError(t, input)
	})

	t.Run("ratecounter block is not empty", func(t *testing.T) {
		input := `
ratecounter req_counter {
	set var.bar = "baz";
}
`
		assertError(t, input)
	})

	t.Run("ratecounter variable should be pass if it is defined", func(t *testing.T) {
		input := `
penaltybox ip_pb {}
ratecounter counter_60 {}

sub test_sub{
	declare local var.ratelimit_exceeded BOOL;
	set var.ratelimit_exceeded = ratelimit.check_rate(
		digest.hash_sha256("123"),
		counter_60,
		1,
		60,
		135,
		ip_pb,
		2m);
}
`
		assertNoError(t, input)
	})

	t.Run("ratecounter variable should be defined", func(t *testing.T) {
		input := `
penaltybox ip_pb {}

sub test_sub{
	declare local var.ratelimit_exceeded BOOL;
	set var.ratelimit_exceeded = ratelimit.check_rate(
		digest.hash_sha256("123"),
		counter_60,
		1,
		60,
		135,
		ip_pb,
		2m);
}
`
		assertError(t, input)
	})

	t.Run("ratecounter bucket variables should pass if the ratecounter is defined", func(t *testing.T) {
		input := `
ratecounter counter_60 {}

sub test_sub{
	set req.http.X-ERL:tls_bucket_10s = std.itoa(ratecounter.counter_60.bucket.10s);
}
`
		assertNoError(t, input)
	})

	t.Run("ratecounter bucket variables should not pass if the ratecounter is not defined", func(t *testing.T) {
		input := `
ratecounter counter_60 {}

sub test_sub{
	set req.http.X-ERL:tls_rate_10s = std.itoa(ratecounter.counter.bucket.10s);
}
`
		assertError(t, input)
	})

	t.Run("ratecounter bucket variables should exist", func(t *testing.T) {
		input := `
ratecounter counter_60 {}

sub test_sub{
	set req.http.X-ERL:tls_bucket_10s = std.itoa(ratecounter.counter_60.bucket.100s);
}
`
		assertError(t, input)
	})
}

func TestLintGotoStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
	sub foo {
		declare local var.x INTEGER;
		set var.x = 1;

		goto set_and_update;

		if (var.x == 1) {
			set var.x = 2;
		}

		set_and_update:
		set var.x = 3;
	}
	`

		assertNoError(t, input)
	})

	t.Run("only one destination is allowed", func(t *testing.T) {
		input := `
	sub foo {
		declare local var.x INTEGER;
		set var.x = 1;

		goto set_and_update;

		if (var.x == 1) {
			set var.x = 2;
		}

		set_and_update:
		set var.x = 3;
		set_and_update:
	}
	`

		assertError(t, input)
	})

	t.Run("undefined goto destination", func(t *testing.T) {
		input := `
	sub foo {
		declare local var.x INTEGER;
		set var.x = 1;

		if (var.x == 1) {
			set var.x = 2;
		}

		set_and_update:
		set var.x = 3;
	}
	`

		assertError(t, input)
	})

	t.Run("goto scope should be one subroutine", func(t *testing.T) {
		input := `
	sub some_function {
		goto foo;
	}
	
	sub another_function {
		foo:
	}
	`

		assertError(t, input)
	})
}

func TestLintFunctionStatement(t *testing.T) {
	t.Run("pass because it is one of Fastly builtin function", func(t *testing.T) {
		input := `
	sub foo {
		std.collect(req.http.Cookie, "|");
	}
	`

		assertNoError(t, input)
	})

	t.Run("cannot call a custom sub as a function statement", func(t *testing.T) {
		input := `
	sub foo {
		log "123";
	}
	
	sub bar {
		foo();
	}
	`

		assertError(t, input)
	})

	t.Run("cannot call a custom sub with return type as a function statement", func(t *testing.T) {
		input := `
	sub foo BOOL {
		log "123";
		return true;
	}
	
	sub bar {
		foo();
	}
	`

		assertError(t, input)
	})
}
