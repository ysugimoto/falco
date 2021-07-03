package lexer

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/token"
)

func TestLexer(t *testing.T) {
	input := `
{" foobar "}
{" foo\"bar "}
import boltsort;
include "feature_mod";

acl internal {
	"192.168.0.1";
	"192.168.0.2"/32;
	!"192.168.0.3";
	!"192.168.0.4"/32;
}

backend example {
	.host = "example.com";
	.probe = {
		.request = "GET / HTTP/1.1";
	}
}

director example_director client {
	.quorum = 20%;
	{ .backend = example; .weight = 1; }
}

table tbl {
	"foo": "bar",
}

# This is a single comment
// This is an another comment
sub vcl_recv {
	/*
		multi-line comment here
	*/
	declare local var.foo INTEGER;
	set req.http.Host = "example.com";
	set var.foo = 1;
	set var.foo += 1;
	set var.foo -= 2;
	set var.foo *= 2;
	set var.foo /= 2;
	set var.foo %= 1;
	set var.foo |= 1;
	set var.foo &= 1;
	set var.foo ^= 1;
	set var.foo <<= 1;
	set var.foo >>= 1;
	set var.foo rol= 1;
	set var.foo ror= 1;
	set var.foo &&= 1;
	set var.foo ||= 1;

	if (req.http.X-Forwarded-For == "192.168.1.2") {
		restart;
	} else if (req.http.Host != "example.com") {
		call mod_recv;
	} elseif (req.http.Host ~ "example") {
		unset req.http.Host;
	} elsif (req.http.Host !~ "example") {
		synthetic "foobar";
    } else {
		error 750;
	}

	add req.http.Cookie:session = uuid.version4();
	esi;
	log syslog "foo";
	unset req.http.Cookie;
	return(pass);
	synthetic.base64 {"foo bar"};
}`

	expects := []token.Token{
		{Type: token.LF, Literal: "\n"},
		{Type: token.STRING, Literal: " foobar "},
		{Type: token.LF, Literal: "\n"},
		{Type: token.STRING, Literal: " foo\"bar "},
		{Type: token.LF, Literal: "\n"},

		// import
		{Type: token.IMPORT, Literal: "import"},
		{Type: token.IDENT, Literal: "boltsort"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		// include
		{Type: token.INCLUDE, Literal: "include"},
		{Type: token.STRING, Literal: "feature_mod"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.LF, Literal: "\n"},

		// acl
		{Type: token.ACL, Literal: "acl"},
		{Type: token.IDENT, Literal: "internal"},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.STRING, Literal: "192.168.0.1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.STRING, Literal: "192.168.0.2"},
		{Type: token.SLASH, Literal: "/"},
		{Type: token.INT, Literal: "32"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.NOT, Literal: "!"},
		{Type: token.STRING, Literal: "192.168.0.3"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.NOT, Literal: "!"},
		{Type: token.STRING, Literal: "192.168.0.4"},
		{Type: token.SLASH, Literal: "/"},
		{Type: token.INT, Literal: "32"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RIGHT_BRACE, Literal: "}"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.LF, Literal: "\n"},

		// backend
		{Type: token.BACKEND, Literal: "backend"},
		{Type: token.IDENT, Literal: "example"},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.DOT, Literal: "."},
		{Type: token.IDENT, Literal: "host"},
		{Type: token.ASSIGN, Literal: "="},
		{Type: token.STRING, Literal: "example.com"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.DOT, Literal: "."},
		{Type: token.IDENT, Literal: "probe"},
		{Type: token.ASSIGN, Literal: "="},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.DOT, Literal: "."},
		{Type: token.IDENT, Literal: "request"},
		{Type: token.ASSIGN, Literal: "="},
		{Type: token.STRING, Literal: "GET / HTTP/1.1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RIGHT_BRACE, Literal: "}"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RIGHT_BRACE, Literal: "}"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.LF, Literal: "\n"},

		// director
		{Type: token.DIRECTOR, Literal: "director"},
		{Type: token.IDENT, Literal: "example_director"},
		{Type: token.IDENT, Literal: "client"},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.DOT, Literal: "."},
		{Type: token.IDENT, Literal: "quorum"},
		{Type: token.ASSIGN, Literal: "="},
		{Type: token.STRING, Literal: "20%"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.DOT, Literal: "."},
		{Type: token.BACKEND, Literal: "backend"},
		{Type: token.ASSIGN, Literal: "="},
		{Type: token.IDENT, Literal: "example"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.DOT, Literal: "."},
		{Type: token.IDENT, Literal: "weight"},
		{Type: token.ASSIGN, Literal: "="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.RIGHT_BRACE, Literal: "}"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RIGHT_BRACE, Literal: "}"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.LF, Literal: "\n"},

		// table
		{Type: token.TABLE, Literal: "table"},
		{Type: token.IDENT, Literal: "tbl"},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.STRING, Literal: "foo"},
		{Type: token.COLON, Literal: ":"},
		{Type: token.STRING, Literal: "bar"},
		{Type: token.COMMA, Literal: ","},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RIGHT_BRACE, Literal: "}"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.LF, Literal: "\n"},

		// single line comment
		{Type: token.COMMENT, Literal: "# This is a single comment"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.COMMENT, Literal: "// This is an another comment"},
		{Type: token.LF, Literal: "\n"},

		// subroutine vcl_recv
		{Type: token.SUBROUTINE, Literal: "sub"},
		{Type: token.IDENT, Literal: "vcl_recv"},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.COMMENT, Literal: "/*\n\t\tmulti-line comment here\n\t*/"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.DECLARE, Literal: "declare"},
		{Type: token.IDENT, Literal: "local"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.IDENT, Literal: "INTEGER"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "req.http.Host"},
		{Type: token.ASSIGN, Literal: "="},
		{Type: token.STRING, Literal: "example.com"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.ASSIGN, Literal: "="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.ADDITION, Literal: "="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.SUBTRACTION, Literal: "-="},
		{Type: token.INT, Literal: "2"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.MULTIPLICATION, Literal: "*="},
		{Type: token.INT, Literal: "2"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.DIVISION, Literal: "/="},
		{Type: token.INT, Literal: "2"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.REMAINDER, Literal: "%="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.BITWISE_OR, Literal: "|="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.BITWISE_AND, Literal: "&="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.BITWISE_XOR, Literal: "^="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.LEFT_SHIFT, Literal: "<<="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.RIGHT_SHIFT, Literal: ">>="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.LEFT_ROTATE, Literal: "rol="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.RIGHT_ROTATE, Literal: "ror="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.LOGICAL_AND, Literal: "&&="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "var.foo"},
		{Type: token.LOGICAL_OR, Literal: "||="},
		{Type: token.INT, Literal: "1"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.IF, Literal: "if"},
		{Type: token.LEFT_PAREN, Literal: "("},
		{Type: token.IDENT, Literal: "req.http.X-Forwarded-For"},
		{Type: token.EQUAL, Literal: "=="},
		{Type: token.STRING, Literal: "192.168.1.2"},
		{Type: token.RIGHT_PAREN, Literal: ")"},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RESTART, Literal: "restart"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RIGHT_BRACE, Literal: "}"},

		{Type: token.ELSE, Literal: "else"},
		{Type: token.IF, Literal: "if"},
		{Type: token.LEFT_PAREN, Literal: "("},
		{Type: token.IDENT, Literal: "req.http.Host"},
		{Type: token.NOT_EQUAL, Literal: "!="},
		{Type: token.STRING, Literal: "example.com"},
		{Type: token.RIGHT_PAREN, Literal: ")"},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.CALL, Literal: "call"},
		{Type: token.IDENT, Literal: "mod_recv"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RIGHT_BRACE, Literal: "}"},

		{Type: token.ELSEIF, Literal: "elseif"},
		{Type: token.LEFT_PAREN, Literal: "("},
		{Type: token.IDENT, Literal: "req.http.Host"},
		{Type: token.REGEX_MATCH, Literal: "~"},
		{Type: token.STRING, Literal: "example"},
		{Type: token.RIGHT_PAREN, Literal: ")"},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.UNSET, Literal: "unset"},
		{Type: token.IDENT, Literal: "req.http.Host"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RIGHT_BRACE, Literal: "}"},

		{Type: token.ELSIF, Literal: "elsif"},
		{Type: token.LEFT_PAREN, Literal: "("},
		{Type: token.IDENT, Literal: "req.http.Host"},
		{Type: token.NOT_REGEX_MATCH, Literal: "!~"},
		{Type: token.STRING, Literal: "example"},
		{Type: token.RIGHT_PAREN, Literal: ")"},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.SYNTHETIC, Literal: "synthetic"},
		{Type: token.STRING, Literal: "foobar"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RIGHT_BRACE, Literal: "}"},

		{Type: token.ELSE, Literal: "else"},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.ERROR, Literal: "error"},
		{Type: token.INT, Literal: "750"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RIGHT_BRACE, Literal: "}"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.ADD, Literal: "add"},
		{Type: token.IDENT, Literal: "req.http.Cookie:session"},
		{Type: token.ASSIGN, Literal: "="},
		{Type: token.IDENT, Literal: "uuid.version4"},
		{Type: token.LEFT_PAREN, Literal: "("},
		{Type: token.RIGHT_PAREN, Literal: ")"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.ESI, Literal: "esi"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.LOG, Literal: "log"},
		{Type: token.IDENT, Literal: "syslog"},
		{Type: token.STRING, Literal: "foo"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.UNSET, Literal: "unset"},
		{Type: token.IDENT, Literal: "req.http.Cookie"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.RETURN, Literal: "return"},
		{Type: token.LEFT_PAREN, Literal: "("},
		{Type: token.IDENT, Literal: "pass"},
		{Type: token.RIGHT_PAREN, Literal: ")"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SYNTHETIC_BASE64, Literal: "synthetic.base64"},
		{Type: token.STRING, Literal: "foo bar"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RIGHT_BRACE, Literal: "}"},
		{Type: token.EOF, Literal: ""},
	}

	l := NewFromString(input)

	for i, tt := range expects {
		tok := l.NextToken()

		if diff := cmp.Diff(tt, tok, cmpopts.IgnoreFields(token.Token{}, "Line", "Position", "Offset")); diff != "" {
			t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
		}
	}
}

func TestLexerLine(t *testing.T) {
	t.Run("include LF in string literal", func(t *testing.T) {
		input := `"foo
bar"`
		expects := []token.Token{
			{Type: token.STRING, Literal: "foo\nbar", Line: 1, Position: 1},
			{Type: token.EOF, Literal: "", Line: 2, Position: 5},
		}

		l := NewFromString(input)
		for i, tt := range expects {
			tok := l.NextToken()

			if diff := cmp.Diff(tt, tok, cmpopts.IgnoreFields(token.Token{}, "Offset")); diff != "" {
				t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
			}
		}
	})

	t.Run("correct line and position with comment lexing", func(t *testing.T) {
		input := `
# This is comment in global
sub vcl_recv {
	// This is comment in subroutine
	set req.http.User-Agent = "foo";

	// When host exists, restart
	if (req.http.Host) {
		restart;
	}

	## Otherwise, set tentative host
	else {
		set req.http.Host = "tentative";
	}
}`
		expects := []token.Token{
			{Type: token.LF, Literal: "\n", Line: 1, Position: 1},
			{Type: token.COMMENT, Literal: "# This is comment in global", Line: 2, Position: 1},
			{Type: token.LF, Literal: "\n", Line: 2, Position: 28},
			{Type: token.SUBROUTINE, Literal: "sub", Line: 3, Position: 1},
			{Type: token.IDENT, Literal: "vcl_recv", Line: 3, Position: 5},
			{Type: token.LEFT_BRACE, Literal: "{", Line: 3, Position: 14},
			{Type: token.LF, Literal: "\n", Line: 3, Position: 15},
			{Type: token.COMMENT, Literal: "// This is comment in subroutine", Line: 4, Position: 2},
			{Type: token.LF, Literal: "\n", Line: 4, Position: 34},
			{Type: token.SET, Literal: "set", Line: 5, Position: 2},
			{Type: token.IDENT, Literal: "req.http.User-Agent", Line: 5, Position: 6},
			{Type: token.ASSIGN, Literal: "=", Line: 5, Position: 26},
			{Type: token.STRING, Literal: "foo", Line: 5, Position: 28},
			{Type: token.SEMICOLON, Literal: ";", Line: 5, Position: 33},
			{Type: token.LF, Literal: "\n", Line: 5, Position: 34},
			{Type: token.LF, Literal: "\n", Line: 6, Position: 1},
			{Type: token.COMMENT, Literal: "// When host exists, restart", Line: 7, Position: 2},
			{Type: token.LF, Literal: "\n", Line: 7, Position: 30},
			{Type: token.IF, Literal: "if", Line: 8, Position: 2},
			{Type: token.LEFT_PAREN, Literal: "(", Line: 8, Position: 5},
			{Type: token.IDENT, Literal: "req.http.Host", Line: 8, Position: 6},
			{Type: token.RIGHT_PAREN, Literal: ")", Line: 8, Position: 19},
			{Type: token.LEFT_BRACE, Literal: "{", Line: 8, Position: 21},
			{Type: token.LF, Literal: "\n", Line: 8, Position: 22},
			{Type: token.RESTART, Literal: "restart", Line: 9, Position: 3},
			{Type: token.SEMICOLON, Literal: ";", Line: 9, Position: 10},
			{Type: token.LF, Literal: "\n", Line: 9, Position: 11},
			{Type: token.RIGHT_BRACE, Literal: "}", Line: 10, Position: 2},
			{Type: token.LF, Literal: "\n", Line: 10, Position: 3},
			{Type: token.LF, Literal: "\n", Line: 11, Position: 1},
			{Type: token.COMMENT, Literal: "## Otherwise, set tentative host", Line: 12, Position: 2},
			{Type: token.LF, Literal: "\n", Line: 12, Position: 34},
			{Type: token.ELSE, Literal: "else", Line: 13, Position: 2},
			{Type: token.LEFT_BRACE, Literal: "{", Line: 13, Position: 7},
			{Type: token.LF, Literal: "\n", Line: 13, Position: 8},
			{Type: token.SET, Literal: "set", Line: 14, Position: 3},
			{Type: token.IDENT, Literal: "req.http.Host", Line: 14, Position: 7},
			{Type: token.ASSIGN, Literal: "=", Line: 14, Position: 21},
			{Type: token.STRING, Literal: "tentative", Line: 14, Position: 23},
			{Type: token.SEMICOLON, Literal: ";", Line: 14, Position: 34},
			{Type: token.LF, Literal: "\n", Line: 14, Position: 35},
			{Type: token.RIGHT_BRACE, Literal: "}", Line: 15, Position: 2},
			{Type: token.LF, Literal: "\n", Line: 15, Position: 3},

			{Type: token.RIGHT_BRACE, Literal: "}", Line: 16, Position: 1},
			{Type: token.EOF, Literal: "", Line: 16, Position: 2},
		}

		l := NewFromString(input)
		for i, tt := range expects {
			tok := l.NextToken()

			if diff := cmp.Diff(tt, tok, cmpopts.IgnoreFields(token.Token{}, "Offset")); diff != "" {
				t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
			}
		}
	})
}

func TestComplecatedStatement(t *testing.T) {
	input := `set var.expires = regsub(var.payload, {"^.*?"exp"\s*:\s*(\d+).*?$"}, "\1");`
	expects := []token.Token{
		{Type: token.SET, Literal: "set", Line: 1, Position: 1},
		{Type: token.IDENT, Literal: "var.expires", Line: 1, Position: 5},
		{Type: token.ASSIGN, Literal: "=", Line: 1, Position: 17},
		{Type: token.IDENT, Literal: "regsub", Line: 1, Position: 19},
		{Type: token.LEFT_PAREN, Literal: "(", Line: 1, Position: 25},
		{Type: token.IDENT, Literal: "var.payload", Line: 1, Position: 26},
		{Type: token.COMMA, Literal: ",", Line: 1, Position: 37},
		{Type: token.STRING, Literal: `^.*?"exp"\s*:\s*(\d+).*?$`, Line: 1, Position: 39},
		{Type: token.COMMA, Literal: ",", Line: 1, Position: 68},
		{Type: token.STRING, Literal: `1`, Line: 1, Position: 70},
		{Type: token.RIGHT_PAREN, Literal: ")", Line: 1, Position: 74},
		{Type: token.SEMICOLON, Literal: ";", Line: 1, Position: 75},
		{Type: token.EOF, Literal: "", Line: 1, Position: 76},
	}

	l := NewFromString(input)
	for i, tt := range expects {
		tok := l.NextToken()

		if diff := cmp.Diff(tt, tok, cmpopts.IgnoreFields(token.Token{}, "Offset")); diff != "" {
			t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
		}
	}
}
