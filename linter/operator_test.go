package linter

import (
	"testing"

	"github.com/ysugimoto/falco/v2/lexer"
	"github.com/ysugimoto/falco/v2/linter/context"
	"github.com/ysugimoto/falco/v2/parser"
)

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

	t.Run("req.backend is comparable with BACKEND type", func(t *testing.T) {
		input := `
backend foo {}
sub foo {
	if (req.backend == foo) {
		restart;
	}
}`
		assertNoError(t, input)
	})

	// Fastly coerces the right operand to STRING for these comparisons.
	// see: https://fiddle.fastly.dev/fiddle/6c2ac451
	t.Run("STRING is comparable with a coercible variable", func(t *testing.T) {
		for _, vclType := range []string{"INTEGER", "FLOAT", "RTIME", "TIME", "BOOL", "IP"} {
			t.Run(vclType, func(t *testing.T) {
				input := `
sub foo {
	declare local var.V ` + vclType + `;
	if (req.http.Host == var.V) {
		restart;
	}
}`
				assertNoError(t, input)
			})
		}
	})

	t.Run("STRING is comparable with BACKEND", func(t *testing.T) {
		input := `
backend foo {}
sub foo {
	if (req.http.Host == foo) {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("STRING is comparable with a coercible function call", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host == std.atoi("10")) {
		restart;
	}
}`
		assertNoError(t, input)
	})

	// Fastly rejects a constant of another type, but accepts a BOOL literal.
	// see: https://fiddle.fastly.dev/fiddle/77b892e1
	t.Run("STRING is not comparable with a constant of another type", func(t *testing.T) {
		for _, constant := range []string{"10", "-10", "10.0", "100s"} {
			t.Run(constant, func(t *testing.T) {
				input := `
sub foo {
	if (req.http.Host == ` + constant + `) {
		restart;
	}
}`
				assertError(t, input)
			})
		}
	})

	t.Run("STRING is comparable with a BOOL literal", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host == true) {
		restart;
	}
}`
		assertNoError(t, input)
	})

	// REGEX is only an operand of the ~ and !~ operators.
	// see: https://fiddle.fastly.dev/fiddle/c5e955d4
	t.Run("STRING is not comparable with REGEX", func(t *testing.T) {
		input := `
table t REGEX {
	"k": "^foo$",
}
sub foo {
	if (req.http.Host == table.lookup_regex(t, "k")) {
		restart;
	}
}`
		assertError(t, input)
	})

	// Fastly parses the right operand as an IP address, constants included.
	// see: https://fiddle.fastly.dev/fiddle/838b27db
	t.Run("IP is comparable with STRING", func(t *testing.T) {
		input := `
sub foo {
	if (client.ip == req.http.Host) {
		restart;
	}
	if (client.ip == "127.0.0.1") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	// Fastly accepts neither parentheses nor a prefix operator on the right
	// operand unless the left operand is BOOL, whatever the operand contains.
	// see: https://fiddle.fastly.dev/fiddle/8f3da311
	t.Run("right operand cannot be grouped or prefixed", func(t *testing.T) {
		for _, cond := range []string{
			`req.http.Host == (10)`,
			`req.http.Host == (-10)`,
			`req.http.Host == -(10)`,
			`req.http.Host == ((10.5))`,
			`req.http.Host == (10s)`,
			`req.http.Host == ("10")`,
			`req.http.Host == (req.vcl.version)`,
			`req.http.Host == (true)`,
			`req.http.Host == !true`,
			`req.http.Host == -req.vcl.version`,
			`req.vcl.version == (10)`,
			`req.vcl.version == -(10)`,
			`req.vcl.version == -req.vcl.version`,
			`req.vcl.version == +10`,
			`req.vcl.version == +req.vcl.version`,
			`client.geo.latitude == (1.0)`,
			`client.geo.latitude == +1.0`,
			`req.max_stale_if_error == (1s)`,
		} {
			t.Run(cond, func(t *testing.T) {
				input := `
sub foo {
	if (` + cond + `) {
		restart;
	}
}`
				assertError(t, input)
			})
		}
	})

	// client.ip is typed STRING, so a declared IP exercises the IP path.
	// see: https://fiddle.fastly.dev/fiddle/8f3da311
	t.Run("IP right operand cannot be grouped", func(t *testing.T) {
		input := `
sub foo {
	declare local var.IP IP;
	if (var.IP == ("127.0.0.1")) {
		restart;
	}
}`
		assertError(t, input)
	})

	// see: https://fiddle.fastly.dev/fiddle/f832d6ac
	t.Run("BACKEND right operand cannot be grouped", func(t *testing.T) {
		input := `
backend F_x {}
sub foo {
	if (req.backend == (F_x)) {
		restart;
	}
}`
		assertError(t, input)
	})

	// Fastly reports the error at the opening parenthesis or prefix operator,
	// on the right operand's own line when the condition spans lines.
	// The line and position checks keep the if's own ( from matching.
	// see: https://fiddle.fastly.dev/fiddle/8f3da311
	t.Run("grouped or prefixed right operand error points at the operand", func(t *testing.T) {
		for _, tc := range []struct {
			cond     string
			literal  string
			line     int
			position int
		}{
			{cond: `req.http.Host == ("10")`, literal: "(", line: 2, position: 23},
			{cond: `req.http.Host == -req.vcl.version`, literal: "-", line: 2, position: 23},
			{cond: `req.http.Host == !true`, literal: "!", line: 2, position: 23},
			{cond: "req.http.Host ==\n\t\t(\"10\")", literal: "(", line: 3, position: 3},
		} {
			t.Run(tc.cond, func(t *testing.T) {
				input := "sub foo {\n\tif (" + tc.cond + ") {\n\t\trestart;\n\t}\n}"
				vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
				if err != nil {
					t.Fatalf("unexpected parser error: %s", err)
				}
				l := New(testConfig)
				l.lint(vcl, context.New())
				if l.FatalError != nil {
					t.Fatalf("fatal error: %s", l.FatalError.Error)
				}
				if len(l.Errors) != 1 {
					t.Fatalf("expected one lint error, got %v", l.Errors)
				}
				got := l.Errors[0]
				if got.Rule != OPERATOR_CONDITIONAL {
					t.Errorf("rule = %s, want %s", got.Rule, OPERATOR_CONDITIONAL)
				}
				if got.Token.Literal != tc.literal || got.Token.Line != tc.line || got.Token.Position != tc.position {
					t.Errorf("error at %q line %d position %d, want %q line %d position %d",
						got.Token.Literal, got.Token.Line, got.Token.Position,
						tc.literal, tc.line, tc.position)
				}
			})
		}
	})

	// see: https://fiddle.fastly.dev/fiddle/ce9285b4
	t.Run("right operand can be a negative literal or a grouped or negated BOOL", func(t *testing.T) {
		for _, cond := range []string{
			`req.vcl.version == -10`,
			`client.geo.latitude == -1.0`,
			`req.max_stale_if_error == -1s`,
			`fastly_info.is_h2 == (true)`,
			`fastly_info.is_h2 == !req.is_ipv6`,
			`fastly_info.is_h2 == (req.http.Host == "x")`,
			`req.http.Host == +req.http.Cookie`,
		} {
			t.Run(cond, func(t *testing.T) {
				input := `
sub foo {
	if (` + cond + `) {
		restart;
	}
}`
				assertNoError(t, input)
			})
		}
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

	// see: https://fiddle.fastly.dev/fiddle/8f3da311
	t.Run("right operand cannot be grouped or prefixed", func(t *testing.T) {
		for _, cond := range []string{
			`req.http.Host != (10)`,
			`req.http.Host != ("10")`,
			`req.http.Host != !true`,
			`req.vcl.version != (10)`,
		} {
			t.Run(cond, func(t *testing.T) {
				input := `
sub foo {
	if (` + cond + `) {
		restart;
	}
}`
				assertError(t, input)
			})
		}
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

	t.Run("pass with PCRE expression", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.Host ~ "(?i)^word") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("pass with expression that has backslash", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.User-Agent ~ "\(compatible.?; Googlebot/2.1.?; \+http://www.google.com/bot.html") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("pass with PCRE expression that has backslash", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.User-Agent ~ "(?i)windows\ ?ce") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("pass with PCRE expression that uses atomic grouping (unsupported by regexp)", func(t *testing.T) {
		input := `
sub foo {
	if (req.http.User-Agent ~ "\b(?>integer|insert|in)\b") {
		restart;
	}
}`
		assertNoError(t, input)
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

func TestLintAdditionAssignOperator(t *testing.T) {
	t.Run("req.hash += string is allowed", func(t *testing.T) {
		input := `
sub vcl_hash {
	#FASTLY HASH
	set req.hash += req.url;
}`
		assertNoError(t, input)
	})

	t.Run("req.hash += string literal is allowed", func(t *testing.T) {
		input := `
sub vcl_hash {
	#FASTLY HASH
	set req.hash += "cache-key";
}`
		assertNoError(t, input)
	})

	t.Run("+= on STRING variable is allowed", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;
	set var.S = "foo";
	set var.S += "bar";
}`
		assertNoError(t, input)
	})

	t.Run("+= on INTEGER type is allowed", func(t *testing.T) {
		input := `
sub foo {
	declare local var.I INTEGER;
	set var.I = 1;
	set var.I += 2;
}`
		assertNoError(t, input)
	})

	t.Run("+= on HTTP header is allowed", func(t *testing.T) {
		input := `
sub foo {
	set req.http.Foo += "bar";
}`
		assertNoError(t, input)
	})

	t.Run("-= on STRING type is disallowed", func(t *testing.T) {
		input := `
sub foo {
	declare local var.S STRING;
	set var.S = "foo";
	set var.S -= "bar";
}`
		assertError(t, input)
	})
}
