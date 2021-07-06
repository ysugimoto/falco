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
	l.Lint(vcl, context.New())
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
	l.Lint(vcl, context.New())
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
	l.Lint(vcl, context.New())
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

}

func TestLintDeclareStatement(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub foo {
	declare local var.item1 STRING;
	declare local var.item2 INTEGER;
	declare local var.item3 FLOAT;
	declare local var.item4 IP;
	declare local var.item5 ID;
	declare local var.item6 ACL;
	declare local var.item7 BACKEND;
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
	declare local var.I INTEGER;

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
	declare local var.S STRING;
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
