package token

import "testing"

// TestCategory pins the token-type -> highlighting-category mapping shared by
// the cmd/wasm and cmd/falco-component builds.
func TestCategory(t *testing.T) {
	cases := []struct {
		tt   TokenType
		want string
	}{
		{SUBROUTINE, "keyword"},
		{IF, "keyword"},
		{STRING, "string"},
		{OPEN_LONG_STRING, "string"},
		{INT, "number"},
		{RTIME, "number"},
		{TRUE, "boolean"},
		{IDENT, "variable"},
		{EQUAL, "operator"},
		{PLUS, "operator"},
		{COMMENT, "comment"},
		{SEMICOLON, "punctuation"},
		{FASTLY_CONTROL, "control"},
		{EOF, "text"},
	}
	for _, c := range cases {
		if got := Category(c.tt); got != c.want {
			t.Errorf("Category(%q) = %q, want %q", c.tt, got, c.want)
		}
	}
}
