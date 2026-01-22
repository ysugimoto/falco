package linter

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/linter/context"
	"github.com/ysugimoto/falco/parser"
)

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
	declare local var.item5 BOOL;
	declare local var.item6 ACL;
	declare local var.item7 BACKEND;

	set var.item1 = "1";
	set var.item2 = 1;
	set var.item3 = 1.0;
	set var.item4 = std.ip("192.168.0.1", "192.168.0.2");
	set var.item5 = true;
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

	t.Run("set backend as req.backend", func(t *testing.T) {
		input := `
backend foo {}
sub bar {
	set req.backend = foo;
}`

		assertNoError(t, input)
	})

	t.Run("pass req.backend as string", func(t *testing.T) {
		input := `
sub foo {
	set req.http.Debug-Backend = req.backend;
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

	t.Run("invalid ident with wildcard", func(t *testing.T) {
		input := `
sub foo {
	set req.http.X-* = "foo";
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

	t.Run("valid with wildcard", func(t *testing.T) {
		input := `
sub foo {
	unset req.http.X-*;
}`
		assertNoError(t, input)
	})

	t.Run("invalid with wildcard position", func(t *testing.T) {
		input := `
sub foo {
	unset req.http.X-*-Bar;
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

	t.Run("pass with function", func(t *testing.T) {
		input := `
sub foo {
	error std.atoi("10");
}
`
		assertNoError(t, input)
	})

	t.Run("invalid function return type", func(t *testing.T) {
		input := `
sub foo {
	error std.strrev("error");
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

	// insert

	t.Run("pass: req.protocol equals https with HSTS header", func(t *testing.T) {
		input := `
// @deliver
sub vcl_deliver {
	#FASTLY DELIVER
	if (req.protocol == "https") {
		set resp.http.Strict-Transport-Security = "max-age=31536000; includeSubDomains";
	}
}`
		assertNoError(t, input)
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

func TestLintSwitchStatement(t *testing.T) {
	t.Run("pass: simple switch", func(t *testing.T) {
		input := `
sub foo {
	switch (req.http.foo) {
	case "bar":
		break;
	}
}`
		assertNoError(t, input)
	})

	t.Run("undefined function in control", func(t *testing.T) {
		input := `
sub foo {
	switch (undefined()) {
	case "bar":
		break;
	}
}`
		assertError(t, input)
	})

	t.Run("bool function in control", func(t *testing.T) {
		input := `
sub boolfn BOOL { return true; }
sub foo {
	switch (boolfn()) {
	case "1":
		break;
	}
}`
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

func TestLintVariadicStringArguments(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
	sub foo {
	  h2.disable_header_compression("Authorization", "Secret");
	}
	`

		assertNoError(t, input)
	})

	t.Run("empty arguments are invalid", func(t *testing.T) {
		input := `
	sub foo {
	  h2.disable_header_compression();
	}
	`

		assertError(t, input)
	})

	t.Run("type error", func(t *testing.T) {
		input := `
	sub foo {
	  h2.disable_header_compression(10);
	}
	`

		assertError(t, input)
	})
}

func TestLintLogStatementr(t *testing.T) {

	tests := []struct {
		name        string
		logStatment string
		shouldError bool
	}{
		{
			name:        "log variable",
			logStatment: "log req.restarts;",
		},
		{
			name:        "log string literal",
			logStatment: "log \"foo\";",
		},
		{
			name:        "log int",
			logStatment: "log 42;",
			shouldError: true,
		},
		{
			name:        "log bool",
			logStatment: "log true;",
			shouldError: true,
		},
		// IP literal fails due to parsing error
		// but it should also fail as a lint error
		// as well.
		{
			name:        "log float",
			logStatment: "log 0.1;",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := fmt.Sprintf(`
	sub foo {
		%s
	}`, tt.logStatment)
			if tt.shouldError {
				assertError(t, input)
			} else {
				assertNoError(t, input)
			}

		})
	}

}

func TestEmptyReturnStatement(t *testing.T) {
	t.Run("Error on state-machine-methods", func(t *testing.T) {
		methodWithMacros := map[string]string{
			"vcl_recv":    "#FASTLY RECV",
			"vcl_hash":    "#FASTLY HASH",
			"vcl_hit":     "#FASTLY HIT",
			"vcl_miss":    "#FASTLY MISS",
			"vcl_pass":    "#FASTLY PASS",
			"vcl_fetch":   "#FASTLY FETCH",
			"vcl_error":   "#FASTLY ERROR",
			"vcl_deliver": "#FASTLY DELIVER",
			"vcl_log":     "#FASTLY LOG",
		}
		for method, macro := range methodWithMacros {
			input := fmt.Sprintf(
				`
sub %s {
	%s
	return;
}`, method, macro)
			assertError(t, input)
		}
	})

	t.Run("Pass on other subroutine", func(t *testing.T) {
		input := `
sub foo {
	return;
}
sub vcl_recv {
	#FASTLY RECV
	call foo;
}`
		assertNoError(t, input)
	})
}

func TestGotoBackwardJump(t *testing.T) {
	t.Run("backward jmp is forbidden", func(t *testing.T) {
		input := `
	sub foo {
		BACKWARD:
		set req.http.Foo = "bar";
		goto BACKWARD;
	}
	`
		assertError(t, input)
	})
}

func TestDeprecatedVariable(t *testing.T) {
	tests := []string{
		"client.class.checker",
		"client.class.filter",
		"client.class.masquerading",
		"client.class.spam",
		"client.display.height",
		"client.display.width",
		"client.display.ppi",
		"client.class.downloader",
		"client.class.feedreader",
		"client.platform.ereader",
		"client.platform.tvplayer",
	}

	for _, tt := range tests {
		input := fmt.Sprintf(`
sub vcl_recv {
  #FASTLY recv
  set req.http.Foo = "deprecated: " %s;
}`, tt)

		vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
		if err != nil {
			t.Errorf("unexpected parser error: %s", err)
			t.FailNow()
		}

		l := New(testConfig)
		l.lint(vcl, context.New())
		if l.FatalError != nil {
			t.Errorf("Fatal error: %s", l.FatalError.Error)
			continue
		}
		if len(l.Errors) == 0 {
			t.Errorf("Expect one lint error but empty returned")
			continue
		}
		e := l.Errors[0]
		if e.Severity != WARNING {
			t.Errorf("Error should be Warning but got %s", e.Severity)
			continue
		}
		if !strings.Contains(e.Message, "deprecated") {
			t.Errorf(`Error message should contains "deprecated", got %s`, e.Message)
			continue
		}
	}
}

func TestRegexGroupedVariables(t *testing.T) {
	tests := []string{
		`
sub foo {
	declare local var.S STRING;
	declare local var.R STRING;
	set var.S = "foo.bar.baz.example.com";
	if (var.S ~ "foo\.(^[.]+)\.(^[.]+)") {
		set var.R = re.group.1;
	}
	if (var.S ~ "foo\.(^[.]+)") {
		set var.R = "";
	}
	set var.R = re.group.2; // notset
}`,
		`
sub foo {
	declare local var.S STRING;
	declare local var.R STRING;
	set var.S = "foo.bar.baz.example.com";
	if (var.S ~ "foo\.(^[.]+)\.(^[.]+)") {
		set var.R = re.group.1;
	}
	// with nothing capture
	if (var.S ~ "foo\.+") {
		set var.R = "";
	}
	set var.R = re.group.1; // notset

}`,
	}

	for _, input := range tests {
		assertErrorWithSeverity(t, input, WARNING)
	}
}

func TestGroupedExpressionInStatement(t *testing.T) {
	tests := []string{
		`
sub vcl_recv {
  #FASTLY recv
  set req.http.foo = (req.http.bar == "example.com");
}`,
		`
sub vcl_recv {
  #FASTLY recv
  set req.http.foo = req.http.bar (req.http.baz == "example.com");
}`,
	}

	for _, input := range tests {
		assertError(t, input)
	}

}
