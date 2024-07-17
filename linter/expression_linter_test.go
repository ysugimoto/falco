package linter

import (
	"fmt"
	"testing"
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
