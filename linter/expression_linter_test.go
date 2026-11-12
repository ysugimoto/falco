package linter

import (
	"fmt"
	"testing"

	"github.com/ysugimoto/falco/v2/lexer"
	"github.com/ysugimoto/falco/v2/linter/context"
	"github.com/ysugimoto/falco/v2/parser"
)

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

	t.Run("fuzzy type check for STRING type argument", func(t *testing.T) {

		tests := []string{
			"req.backend",
			"fastly_info.is_h2",
			"client.socket.ploss",
		}
		for _, c := range tests {
			input := fmt.Sprintf(`
			sub foo {
				declare local var.S STRING;
				set var.S = substr(%s, 1);
			}
			`, c)
			assertNoError(t, input)
		}

	})
}

// Each case links the fiddle showing how the Fastly compiler treats it.
func TestLintUtf8Translate(t *testing.T) {
	wrap := func(call string) string {
		return fmt.Sprintf(`
sub foo {
	declare local var.S STRING;
	set var.S = %s;
}`, call)
	}

	passes := []struct {
		name   string
		call   string
		fiddle string
	}{
		{
			name:   "literal sets",
			call:   `utf8.translate(req.http.Foo, "a", "b")`,
			fiddle: "https://fiddle.fastly.dev/fiddle/d148fab2",
		},
		{
			name:   "long string sets",
			call:   `utf8.translate("abc", {"ab"}, {"xy"})`,
			fiddle: "https://fiddle.fastly.dev/fiddle/9b8138e7",
		},
		{
			name:   "duplicates in set2",
			call:   `utf8.translate("abc", "ab", "xx")`,
			fiddle: "https://fiddle.fastly.dev/fiddle/be9bd4f2",
		},
		{
			name:   "set1 duplicate hidden after NUL",
			call:   `utf8.translate("abc", "a%00a", "x")`,
			fiddle: "https://fiddle.fastly.dev/fiddle/6d79ace2",
		},
		{
			name:   "set2 excess hidden after NUL",
			call:   `utf8.translate("abc", "ab", "x%00yz")`,
			fiddle: "https://fiddle.fastly.dev/fiddle/9d0fbb06",
		},
		{
			name:   "no escape decoding in long strings",
			call:   `utf8.translate("abc", {"a%61"}, {"wxyz"})`,
			fiddle: "https://fiddle.fastly.dev/fiddle/741995e0",
		},
	}
	for _, tt := range passes {
		t.Run("pass with "+tt.name, func(t *testing.T) {
			t.Log("Fastly behaviour:", tt.fiddle)
			assertNoError(t, wrap(tt.call))
		})
	}

	// Fastly reports one error per call, checking literal sets first, then
	// empty sets, then excess characters in set2, then duplicates in set1.
	errs := []struct {
		name    string
		call    string
		message string
		token   string
		fiddle  string
	}{
		{
			name:    "set1 is a variable",
			call:    `utf8.translate("abc", req.http.Set, "x")`,
			message: "The set1 argument of utf8.translate must be a string literal.",
			token:   "req.http.Set",
			fiddle:  "https://fiddle.fastly.dev/fiddle/2cfbdd6b",
		},
		{
			name:    "set2 is a variable",
			call:    `utf8.translate("abc", "a", req.http.Set)`,
			message: "The set2 argument of utf8.translate must be a string literal.",
			token:   "req.http.Set",
			fiddle:  "https://fiddle.fastly.dev/fiddle/01d27a8a",
		},
		{
			name:    "empty set1",
			call:    `utf8.translate("abc", "", "x")`,
			message: "Characters required in set1",
			token:   "",
			fiddle:  "https://fiddle.fastly.dev/fiddle/392bf1f7",
		},
		{
			name:    "empty set2",
			call:    `utf8.translate("abc", "a", "")`,
			message: "Characters required in set2",
			token:   "",
			fiddle:  "https://fiddle.fastly.dev/fiddle/1ed328ca",
		},
		{
			name:    "set2 longer than set1",
			call:    `utf8.translate("abc", "ab", "xyz")`,
			message: "Excess characters in set2: Expected 2 or fewer, got 3",
			token:   "xyz",
			fiddle:  "https://fiddle.fastly.dev/fiddle/70aeafb2",
		},
		{
			name:    "duplicate in set1",
			call:    `utf8.translate("abc", "aba", "xyz")`,
			message: "Duplicate character in set1: U+0061",
			token:   "aba",
			fiddle:  "https://fiddle.fastly.dev/fiddle/811ca087",
		},
		{
			name:    "duplicate in set1 after escape decoding",
			call:    `utf8.translate("abc", "a%61", "xy")`,
			message: "Duplicate character in set1: U+0061",
			token:   "a%61",
			fiddle:  "https://fiddle.fastly.dev/fiddle/b49d2ec8",
		},
		{
			name:    "duplicate astral code point in set1",
			call:    `utf8.translate("abc", "🌸a🌸", "xyz")`,
			message: "Duplicate character in set1: U+1F338",
			token:   "🌸a🌸",
			fiddle:  "https://fiddle.fastly.dev/fiddle/aff35cda",
		},
		{
			name:    "empty set1 reported after non-literal set2",
			call:    `utf8.translate("abc", "", req.http.Set)`,
			message: "The set2 argument of utf8.translate must be a string literal.",
			token:   "req.http.Set",
			fiddle:  "https://fiddle.fastly.dev/fiddle/928bdc76",
		},
		{
			name:    "duplicate reported after non-literal set2",
			call:    `utf8.translate("abc", "aa", req.http.Set)`,
			message: "The set2 argument of utf8.translate must be a string literal.",
			token:   "req.http.Set",
			fiddle:  "https://fiddle.fastly.dev/fiddle/4b1b743a",
		},
		{
			name:    "duplicate reported after empty set2",
			call:    `utf8.translate("abc", "aa", "")`,
			message: "Characters required in set2",
			token:   "",
			fiddle:  "https://fiddle.fastly.dev/fiddle/9d41d89e",
		},
		{
			name:    "duplicate reported after excess in set2",
			call:    `utf8.translate("abc", "aa", "xyz")`,
			message: "Excess characters in set2: Expected 2 or fewer, got 3",
			token:   "xyz",
			fiddle:  "https://fiddle.fastly.dev/fiddle/12d7f844",
		},
	}
	for _, tt := range errs {
		t.Run(tt.name, func(t *testing.T) {
			t.Log("Fastly behaviour:", tt.fiddle)
			assertErrorMessage(t, wrap(tt.call), tt.message, tt.token)
		})
	}
}

func TestH2Push(t *testing.T) {
	t.Run("pass: h2.push with one argument", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	if (fastly_info.is_h2 && req.url == "/html") {
		h2.push("/image/png");
	}
}`
		assertNoError(t, input)
	})

	t.Run("pass: h2.push with two arguments", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	if (fastly_info.is_h2 && req.url == "/html") {
		h2.push("/image/png", "image");
	}
}`
		assertNoError(t, input)
	})

	t.Run("error: h2.push with no arguments", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	h2.push();
}`
		assertError(t, input)
	})

	t.Run("error: h2.push with too many arguments", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	h2.push("/image/png", "image", "extra");
}`
		assertError(t, input)
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
	#FASTLY recv
	return (pass);
}`
		assertNoError(t, input)
	})

	t.Run("pass: with reserved word", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	return (restart);
}`
		assertNoError(t, input)
	})

	t.Run("sub: return correct type", func(t *testing.T) {
		input := `
sub custom_sub INTEGER {
	#FASTLY recv
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
	#FASTLY recv
	{
		log "vcl_recv";
	}
}`
	assertNoError(t, input)
}

func TestBlockSyntaxInsideBlockStatementmultiply(t *testing.T) {
	input := `
sub vcl_recv {
	#FASTLY recv
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
	#FASTLY recv
	if (req.url ~ "^/([^\?]*)?(\?.*)?$") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("error: invalid regex", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	if (req.url ~ "^/([^\?]*)?(\?.*?$") {
		restart;
	}
}`
		assertError(t, input)
	})
}

func TestStringConcatenation(t *testing.T) {
	tests := []struct {
		name      string
		statement string
		isError   bool
	}{
		{
			name:      "normal concatenation",
			statement: `set req.http.Foo = "foo" + "bar" "baz";`,
		},
		{
			name:      "invalid group expression",
			statement: `set req.http.Foo = ("foo" + "bar") + "baz";`,
			isError:   true,
		},
		{
			name:      "invalid group expression 2",
			statement: `set req.http.Foo = "foo" + (now + 5m) + "; bar";`,
			isError:   true,
		},
		{
			name:      "INTEGER concatenation",
			statement: `set req.http.Foo = "foo" + 1;`,
			isError:   true,
		},
		{
			name:      "INTEGER concatenation 2",
			statement: `set req.http.Foo = "foo" + -1;`,
			isError:   true,
		},
		{
			name:      "FLOAT concatenation",
			statement: `set req.http.Foo = "foo" + 0.5;`,
			isError:   true,
		},
		{
			name:      "RTIME concatenation",
			statement: `set req.http.Foo = "foo" + 6s;`,
			isError:   true,
		},
		{
			name:      "TIME concatenation",
			statement: `set req.http.Foo = "foo" + now;`,
		},
		{
			name:      "FunctionCall expression concatenation",
			statement: `set req.http.Foo = "foo" + std.atoi("foo");`,
		},
		{
			name:      "if expression concatenation, returns string",
			statement: `set req.http.Foo = "foo" + if(req.http.Bar, "1", "0");`,
		},
		{
			name:      "if expression concatenation, returns constant",
			statement: `set req.http.Foo = "foo" + if(req.http.Bar, 1, 0);`,
			isError:   true,
		},
		{
			name:      "if expression concatenation, returns not string",
			statement: `set req.http.Foo = "foo" + if(req.http.Bar, 1, 0);`,
			isError:   true,
		},
		{
			name:      "prefix expression concatenation",
			statement: `set req.http.Foo = "foo" + !req.http.Bar;`,
			isError:   true,
		},
	}

	vcl := `
sub vcl_recv {
	#FASTLY recv
	%s
}`

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := fmt.Sprintf(vcl, tt.statement)
			vcl, err := parser.New(lexer.NewFromString(code)).ParseVCL()
			if tt.isError {
				if err != nil {
					return
				}
				l := New(testConfig)
				l.lint(vcl, context.New())
				var errs int
				for i := range l.Errors {
					if l.Errors[i].Severity == ERROR {
						errs++
					}
				}
				if errs == 0 {
					t.Errorf("Expects error, but linter reports no error")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected parse error: %s", err)
				t.FailNow()
			}

			l := New(testConfig)
			l.lint(vcl, context.New())
			var errs int
			for i := range l.Errors {
				if l.Errors[i].Severity == ERROR {
					errs++
				}
			}
			if errs > 0 {
				t.Errorf("Lint error: %s", l.Errors)
			}
			if l.FatalError != nil {
				t.Errorf("Fatal error: %s", l.FatalError.Error)
			}
		})
	}
}

func assertConditionalOperatorError(t *testing.T, input string) {
	t.Helper()

	vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
	if err != nil {
		t.Fatalf("unexpected parser error: %s", err)
	}
	l := New(testConfig)
	l.lint(vcl, context.New())
	for _, lintErr := range l.Errors {
		if lintErr.Rule == OPERATOR_CONDITIONAL && lintErr.Severity == ERROR {
			return
		}
	}
	t.Errorf("expected %s error, got %v", OPERATOR_CONDITIONAL, l.Errors)
}

func TestStringConcatenationInConditions(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		wantError bool
	}{
		{
			name:      "reject explicit concatenation in comparison",
			condition: `req.http.Origin == "https://" + req.http.Host`,
			wantError: true,
		},
		{
			name:      "reject concatenation in comparison left operand",
			condition: `req.http.Host + "://" == req.http.Host`,
			wantError: true,
		},
		{
			name:      "reject implicit concatenation in comparison",
			condition: `req.http.Host == "https://" req.http.Host`,
			wantError: true,
		},
		{
			name:      "allow concatenation in if expression value",
			condition: `req.http.Host == if(req.http.Host, "https://" + req.http.Host, "fallback")`,
		},
		{
			name:      "allow concatenation in function argument",
			condition: `std.tolower("https://" + req.http.Host) == "https://example.com"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := fmt.Sprintf(`sub foo {
	if (%s) {
		restart;
	}
}`, tt.condition)
			if !tt.wantError {
				assertNoError(t, input)
				return
			}

			assertConditionalOperatorError(t, input)
		})
	}
}

func TestStringConcatenationInIfExpressionCondition(t *testing.T) {
	input := `sub foo {
	set req.http.Result = if(req.http.Host + "x", "foo", "bar");
}`
	assertConditionalOperatorError(t, input)
}

func TestStringConcatenationInNestedIfExpressionCondition(t *testing.T) {
	input := `sub foo {
	if (std.tolower(if(req.http.Host + "x", "foo", "bar")) == "foo") {
		restart;
	}
}`
	assertConditionalOperatorError(t, input)
}

func TestStringConcatenationIssue360(t *testing.T) {
	// https://github.com/ysugimoto/falco/issues/360
	tests := []struct {
		name    string
		input   string
		isError bool
	}{
		{
			name: "concat RTIME to left string",
			input: `
  sub vcl_deliver {
  	#FASTLY deliver
  	set resp.http.Set-Cookie = "test=abc; domain=fiddle.fastly.dev; path=/; expires=" 5m ";";
  }
  `,
			isError: true,
		},
		{
			name: "concat RTIME to left string with explicit plus sign",
			input: `
  sub vcl_deliver {
  	#FASTLY deliver
  	set resp.http.Set-Cookie = "test=abc; domain=fiddle.fastly.dev; path=/; expires=" + 5m ";";
  }
  `,
			isError: true,
		},
		{
			name: "concat RTIME to left TIME with explicit plus sign",
			input: `
 sub vcl_deliver {
 	#FASTLY deliver
 	set resp.http.Set-Cookie = "test=abc; domain=fiddle.fastly.dev; path=/; expires=" now + 5m ";";
 }
 `,
		},
		{
			name: "concat RTIME to left TIME without plus sign",
			input: `
  sub vcl_deliver {
  	#FASTLY deliver
  	set resp.http.Set-Cookie = "test=abc; domain=fiddle.fastly.dev; path=/; expires=" now 5m ";";
  }
  `,
			isError: true,
		},
		{
			name: "concat RTIME variable to left TIME with plus sign",
			input: `
 sub vcl_deliver {
 	#FASTLY deliver
	declare local var.R RTIME;
	set var.R = 5m;
 	set resp.http.Set-Cookie = "test=abc; domain=fiddle.fastly.dev; path=/; expires=" now + var.R ";";
 }
 `,
			isError: true,
		},
		{
			name: "complicated concatenation for common set-cookie expression",
			input: `
 sub vcl_deliver {
 	#FASTLY deliver
	set resp.http.Set-Cookie = "test=abc; domain=fiddle.fastly.dev; path=/; expires=" time.add(now, 3600s) if(req.http.Foo == "bar", std.atoi("1"), std.atoi("2")) ";";
 }
 `,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vcl, err := parser.New(lexer.NewFromString(tt.input)).ParseVCL()
			if tt.isError {
				if err != nil {
					return
				}
				l := New(testConfig)
				l.lint(vcl, context.New())
				var errs int
				for i := range l.Errors {
					if l.Errors[i].Severity == ERROR {
						errs++
					}
				}
				if errs == 0 {
					t.Errorf("Expects error, but linter reports no error")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected parse error: %s", err)
				t.FailNow()
			}

			l := New(testConfig)
			l.lint(vcl, context.New())
			var errs int
			for i := range l.Errors {
				if l.Errors[i].Severity == ERROR {
					errs++
				}
			}
			if errs > 0 {
				t.Errorf("Lint error: %s", l.Errors)
			}
			if l.FatalError != nil {
				t.Errorf("Fatal error: %s", l.FatalError.Error)
			}
		})
	}
}

func TestLintRegexUrlExtension(t *testing.T) {
	t.Run("warning: req.url with single extension regex", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	if (req.url ~ "\.jpg$") {
		restart;
	}
}`
		assertErrorWithSeverity(t, input, WARNING)
	})

	t.Run("warning: req.url.path with single extension regex", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	if (req.url.path ~ "\.png$") {
		restart;
	}
}`
		assertErrorWithSeverity(t, input, WARNING)
	})

	t.Run("warning: req.url.path with multiple extensions regex", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	if (req.url.path ~ "\.(avif|gif|jpg|png|webp)$") {
		restart;
	}
}`
		assertErrorWithSeverity(t, input, WARNING)
	})

	t.Run("warning: negated regex match", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	if (req.url !~ "\.css$") {
		restart;
	}
}`
		assertErrorWithSeverity(t, input, WARNING)
	})

	t.Run("pass: req.url with non-extension regex", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	if (req.url ~ "^/api/") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("pass: req.url.ext comparison", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	if (req.url.ext == "jpg") {
		restart;
	}
}`
		assertNoError(t, input)
	})

	t.Run("pass: other variable with extension regex", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	if (req.http.X-Original-URL ~ "\.jpg$") {
		restart;
	}
}`
		assertNoError(t, input)
	})
}
