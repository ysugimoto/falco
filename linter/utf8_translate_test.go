package linter

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/v2/lexer"
	"github.com/ysugimoto/falco/v2/linter/context"
	"github.com/ysugimoto/falco/v2/parser"
)

func TestUtf8TranslateSets(t *testing.T) {
	tests := []struct {
		name string
		args string
		// The lint error the call must raise, or empty when the call is good.
		expect string
	}{
		{
			name: "both character sets are string literals",
			args: `req.http.X-Input, "abc", "de"`,
		},
		{
			name: "set2 is measured in characters, not in bytes",
			args: `req.http.X-Input, "a", "é"`,
		},
		{
			name:   "set1 must not be empty",
			args:   `req.http.X-Input, "", "b"`,
			expect: "Characters required in set1",
		},
		{
			name:   "set2 must not be empty",
			args:   `req.http.X-Input, "a", ""`,
			expect: "Characters required in set2",
		},
		{
			name:   "set2 must not be longer than set1",
			args:   `req.http.X-Input, "a", "bc"`,
			expect: "Excess characters in set2: Expected 1 or fewer, got 2",
		},
		{
			name:   "set2 counts characters outside the Basic Multilingual Plane once",
			args:   `req.http.X-Input, "a", "🌸🌼"`,
			expect: "Excess characters in set2: Expected 1 or fewer, got 2",
		},
		{
			name:   "a character set must not come from a variable",
			args:   `req.http.X-Input, req.http.X-Set, "b"`,
			expect: "The character sets of utf8.translate must be string literals.",
		},
		{
			name:   "a character set must not come from a function call",
			args:   `req.http.X-Input, "a", std.tolower("B")`,
			expect: "The character sets of utf8.translate must be string literals.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := fmt.Sprintf(`
sub vcl_recv {
  #FASTLY RECV
  set req.http.X-Translated = utf8.translate(%s);
}
`, tt.args)
			vcl, err := parser.New(lexer.NewFromString(input)).ParseVCL()
			if err != nil {
				t.Fatalf("unexpected parser error: %s", err)
			}

			l := New(testConfig)
			l.lint(vcl, context.New())

			var message string
			if len(l.Errors) > 0 {
				message = l.Errors[0].Message
			}
			if diff := cmp.Diff(tt.expect, message); diff != "" {
				t.Errorf("Lint error unmatch, diff=%s", diff)
			}
		})
	}
}
