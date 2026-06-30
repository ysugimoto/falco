package lexer

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/ysugimoto/falco/v2/token"
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

	unset req.http.X-*;
	add req.http.Cookie:session = uuid.version4();
	esi;
	log syslog "foo";
	unset req.http.Cookie;
	return(pass);
	synthetic.base64 {"foo bar"};

	synthetic.base64 {JSON"
      {"foo": "bar"}
"JSON};

	switch (req.url) {
	case "/":
		esi;
		break;
	case ~ "[2-3]":
		esi;
		fallthrough;
	default:
		esi;
		break;
	}

	set req.http.default:foo = "bar";
	set req.http.pk = {"-----BEGIN PUBLIC KEY-----
aabbccddIieEffggHHhEXAMPLEPUBLICKEY
-----END PUBLIC KEY-----"};
}`

	expects := []token.Token{
		{Type: token.LF, Literal: "\n"},
		{Type: token.OPEN_LONG_STRING, Literal: ""},
		{Type: token.STRING, Literal: " foobar "},
		{Type: token.CLOSE_LONG_STRING, Literal: ""},
		{Type: token.LF, Literal: "\n"},
		{Type: token.OPEN_LONG_STRING, Literal: ""},
		{Type: token.STRING, Literal: ` foo\"bar `},
		{Type: token.CLOSE_LONG_STRING, Literal: ""},
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
		{Type: token.INT, Literal: "20"},
		{Type: token.PERCENT, Literal: "%"},
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
		{Type: token.ADDITION, Literal: "+="},
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

		// wildcard unset
		{Type: token.UNSET, Literal: "unset"},
		{Type: token.IDENT, Literal: "req.http.X-*"},
		{Type: token.SEMICOLON, Literal: ";"},
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
		{Type: token.OPEN_LONG_STRING, Literal: ""},
		{Type: token.STRING, Literal: "foo bar"},
		{Type: token.CLOSE_LONG_STRING, Literal: ""},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SYNTHETIC_BASE64, Literal: "synthetic.base64"},
		{Type: token.OPEN_LONG_STRING, Literal: `JSON`},
		{Type: token.STRING, Literal: "\n      {\"foo\": \"bar\"}\n"},
		{Type: token.CLOSE_LONG_STRING, Literal: `JSON`},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.SWITCH, Literal: "switch"},
		{Type: token.LEFT_PAREN, Literal: "("},
		{Type: token.IDENT, Literal: "req.url"},
		{Type: token.RIGHT_PAREN, Literal: ")"},
		{Type: token.LEFT_BRACE, Literal: "{"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.CASE, Literal: "case"},
		{Type: token.STRING, Literal: "/"},
		{Type: token.COLON, Literal: ":"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.ESI, Literal: "esi"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.BREAK, Literal: "break"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.CASE, Literal: "case"},
		{Type: token.REGEX_MATCH, Literal: "~"},
		{Type: token.STRING, Literal: "[2-3]"},
		{Type: token.COLON, Literal: ":"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.ESI, Literal: "esi"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.FALLTHROUGH, Literal: "fallthrough"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.DEFAULT, Literal: "default"},
		{Type: token.COLON, Literal: ":"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.ESI, Literal: "esi"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.BREAK, Literal: "break"},
		{Type: token.SEMICOLON, Literal: ";"},
		{Type: token.LF, Literal: "\n"},
		{Type: token.RIGHT_BRACE, Literal: "}"},
		{Type: token.LF, Literal: "\n"},

		{Type: token.LF, Literal: "\n"},
		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "req.http.default:foo"},
		{Type: token.ASSIGN, Literal: "="},
		{Type: token.STRING, Literal: "bar"},
		{Type: token.SEMICOLON, Literal: ";"},

		// Multiline string
		{Type: token.LF, Literal: "\n"},
		{Type: token.SET, Literal: "set"},
		{Type: token.IDENT, Literal: "req.http.pk"},
		{Type: token.ASSIGN, Literal: "="},
		{Type: token.OPEN_LONG_STRING, Literal: ""},
		{Type: token.STRING, Literal: "-----BEGIN PUBLIC KEY-----\naabbccddIieEffggHHhEXAMPLEPUBLICKEY\n-----END PUBLIC KEY-----"},
		{Type: token.CLOSE_LONG_STRING, Literal: ""},
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
		{Type: token.OPEN_LONG_STRING, Literal: "", Line: 1, Position: 39},
		{Type: token.STRING, Literal: `^.*?"exp"\s*:\s*(\d+).*?$`, Line: 1, Position: 40},
		{Type: token.CLOSE_LONG_STRING, Literal: "", Line: 1, Position: 67},
		{Type: token.COMMA, Literal: ",", Line: 1, Position: 68},
		{Type: token.STRING, Literal: `\1`, Line: 1, Position: 70},
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

func TestEscapeSequence(t *testing.T) {
	input := `"\1"`
	expects := []token.Token{
		{Type: token.STRING, Literal: "\\1", Line: 1, Position: 1},
		{Type: token.EOF, Literal: "", Line: 1, Position: 5},
	}
	l := NewFromString(input)
	for i, tt := range expects {
		tok := l.NextToken()

		if diff := cmp.Diff(tt, tok, cmpopts.IgnoreFields(token.Token{}, "Offset")); diff != "" {
			t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
		}
	}
}

func TestPeekToken(t *testing.T) {
	input := `set var.expires`
	l := NewFromString(input)

	tok := l.NextToken()
	if diff := cmp.Diff(token.Token{Type: token.SET}, tok, cmpopts.IgnoreFields(token.Token{}, "Literal", "Line", "Position", "Offset")); diff != "" {
		t.Errorf(`Assertion failed, diff= %s`, diff)
	}

	tok = l.PeekToken()
	if diff := cmp.Diff(token.Token{Type: token.IDENT}, tok, cmpopts.IgnoreFields(token.Token{}, "Literal", "Line", "Position", "Offset")); diff != "" {
		t.Errorf(`Assertion failed, diff= %s`, diff)
	}

	tok = l.NextToken()
	if diff := cmp.Diff(token.Token{Type: token.IDENT}, tok, cmpopts.IgnoreFields(token.Token{}, "Literal", "Line", "Position", "Offset")); diff != "" {
		t.Errorf(`Assertion failed, diff= %s`, diff)
	}

	tok = l.NextToken()
	if diff := cmp.Diff(token.Token{Type: token.EOF}, tok, cmpopts.IgnoreFields(token.Token{}, "Literal", "Line", "Position", "Offset")); diff != "" {
		t.Errorf(`Assertion failed, diff= %s`, diff)
	}
}

func TestCustomToken(t *testing.T) {
	input := `describe foo {}`
	l := NewFromString(input, WithCustomTokens(map[string]token.TokenType{
		"describe": token.Custom("DESCRIBE"),
	}))

	expects := []token.Token{
		{Type: token.TokenType("DESCRIBE"), Literal: "describe", Line: 1, Position: 1},
		{Type: token.IDENT, Literal: "foo", Line: 1, Position: 10},
		{Type: token.LEFT_BRACE, Literal: "{", Line: 1, Position: 14},
		{Type: token.RIGHT_BRACE, Literal: "}", Line: 1, Position: 15},
		{Type: token.EOF, Literal: "", Line: 1, Position: 16},
	}
	for i, tt := range expects {
		tok := l.NextToken()

		if diff := cmp.Diff(tt, tok, cmpopts.IgnoreFields(token.Token{}, "Offset")); diff != "" {
			t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
		}
	}
}

func TestHexIntegerLiterals(t *testing.T) {
	tests := []struct {
		name  string
		input string
		expects []token.Token
	}{
		{
			name:  "lowercase hex",
			input: "0x5a5a",
			expects: []token.Token{
				{Type: token.INT, Literal: "0x5a5a", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 7},
			},
		},
		{
			name:  "uppercase hex digits",
			input: "0x7FFFFFFFFFFFFFFF",
			expects: []token.Token{
				{Type: token.INT, Literal: "0x7FFFFFFFFFFFFFFF", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 19},
			},
		},
		{
			name:  "uppercase X prefix",
			input: "0Xff",
			expects: []token.Token{
				{Type: token.INT, Literal: "0Xff", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 5},
			},
		},
		{
			name:  "negative hex",
			input: "-0x8000000000000000",
			expects: []token.Token{
				{Type: token.MINUS, Literal: "-", Line: 1, Position: 1},
				{Type: token.INT, Literal: "0x8000000000000000", Line: 1, Position: 2},
				{Type: token.EOF, Literal: "", Line: 1, Position: 20},
			},
		},
		{
			name:  "hex followed by semicolon",
			input: "0x1f;",
			expects: []token.Token{
				{Type: token.INT, Literal: "0x1f", Line: 1, Position: 1},
				{Type: token.SEMICOLON, Literal: ";", Line: 1, Position: 5},
				{Type: token.EOF, Literal: "", Line: 1, Position: 6},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewFromString(tt.input)
			for i, want := range tt.expects {
				tok := l.NextToken()
				if diff := cmp.Diff(want, tok, cmpopts.IgnoreFields(token.Token{}, "Offset")); diff != "" {
					t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
				}
			}
		})
	}
}

func TestFloatLiterals(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expects []token.Token
	}{
		{
			name:  "decimal exponent",
			input: "1e3",
			expects: []token.Token{
				{Type: token.FLOAT, Literal: "1e3", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 4},
			},
		},
		{
			name:  "negative exponent",
			input: "1e-3",
			expects: []token.Token{
				{Type: token.FLOAT, Literal: "1e-3", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 5},
			},
		},
		{
			name:  "positive exponent",
			input: "1e+3",
			expects: []token.Token{
				{Type: token.FLOAT, Literal: "1e+3", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 5},
			},
		},
		{
			name:  "fractional with exponent",
			input: "1.5e3",
			expects: []token.Token{
				{Type: token.FLOAT, Literal: "1.5e3", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 6},
			},
		},
		{
			name:  "negative fractional with negative exponent",
			input: "-1.2e-3",
			expects: []token.Token{
				{Type: token.MINUS, Literal: "-", Line: 1, Position: 1},
				{Type: token.FLOAT, Literal: "1.2e-3", Line: 1, Position: 2},
				{Type: token.EOF, Literal: "", Line: 1, Position: 8},
			},
		},
		{
			name:  "hex float with p exponent",
			input: "0x1.8p3",
			expects: []token.Token{
				{Type: token.FLOAT, Literal: "0x1.8p3", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 8},
			},
		},
		{
			name:  "hex float without p exponent",
			input: "0x1.8",
			expects: []token.Token{
				{Type: token.FLOAT, Literal: "0x1.8", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 6},
			},
		},
		{
			name:  "hex float without fractional part",
			input: "0x1p3",
			expects: []token.Token{
				{Type: token.FLOAT, Literal: "0x1p3", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 6},
			},
		},
		{
			name:  "uppercase E is not an exponent",
			input: "1E3",
			expects: []token.Token{
				{Type: token.INT, Literal: "1", Line: 1, Position: 1},
				{Type: token.IDENT, Literal: "E3", Line: 1, Position: 2},
				{Type: token.EOF, Literal: "", Line: 1, Position: 4},
			},
		},
		{
			name:  "exponent followed by semicolon",
			input: "1e3;",
			expects: []token.Token{
				{Type: token.FLOAT, Literal: "1e3", Line: 1, Position: 1},
				{Type: token.SEMICOLON, Literal: ";", Line: 1, Position: 4},
				{Type: token.EOF, Literal: "", Line: 1, Position: 5},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewFromString(tt.input)
			for i, want := range tt.expects {
				tok := l.NextToken()
				if diff := cmp.Diff(want, tok, cmpopts.IgnoreFields(token.Token{}, "Offset")); diff != "" {
					t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
				}
			}
		})
	}
}

// TestNumberRTimeInteraction verifies that only plain decimal literals combine
// with an RTIME unit suffix. Hexadecimal and exponent literals must NOT fold
// into an RTIME token; the unit letter is lexed as a separate IDENT so the
// parser rejects the construct rather than misattributing it to RTIME.
func TestNumberRTimeInteraction(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expects []token.Token
	}{
		{
			name:  "plain decimal RTIME still works",
			input: "100ms",
			expects: []token.Token{
				{Type: token.RTIME, Literal: "100ms", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 6},
			},
		},
		{
			name:  "decimal float RTIME still works",
			input: "1.5s",
			expects: []token.Token{
				{Type: token.RTIME, Literal: "1.5s", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 5},
			},
		},
		{
			name:  "exponent literal does not become RTIME",
			input: "1e3s",
			expects: []token.Token{
				{Type: token.FLOAT, Literal: "1e3", Line: 1, Position: 1},
				{Type: token.IDENT, Literal: "s", Line: 1, Position: 4},
				{Type: token.EOF, Literal: "", Line: 1, Position: 5},
			},
		},
		{
			name:  "hex literal does not become RTIME",
			input: "0x1fs",
			expects: []token.Token{
				{Type: token.INT, Literal: "0x1f", Line: 1, Position: 1},
				{Type: token.IDENT, Literal: "s", Line: 1, Position: 5},
				{Type: token.EOF, Literal: "", Line: 1, Position: 6},
			},
		},
		{
			name:  "hex literal with d unit does not become RTIME",
			input: "0x1ds",
			expects: []token.Token{
				{Type: token.INT, Literal: "0x1d", Line: 1, Position: 1},
				{Type: token.IDENT, Literal: "s", Line: 1, Position: 5},
				{Type: token.EOF, Literal: "", Line: 1, Position: 6},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewFromString(tt.input)
			for i, want := range tt.expects {
				tok := l.NextToken()
				if diff := cmp.Diff(want, tok, cmpopts.IgnoreFields(token.Token{}, "Offset")); diff != "" {
					t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
				}
			}
		})
	}
}

// TestMalformedNumberLiterals documents the lexer's deliberately permissive
// contract: malformed numeric literals are still tokenized (and rejected later
// by the parser) rather than failing at lex time. These lock the lex-accepts /
// parse-rejects boundary so it cannot silently regress.
func TestMalformedNumberLiterals(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expects []token.Token
	}{
		{
			name:  "bare hex prefix",
			input: "0x",
			expects: []token.Token{
				{Type: token.INT, Literal: "0x", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 3},
			},
		},
		{
			name:  "hex prefix with non-hex letter",
			input: "0xG",
			expects: []token.Token{
				{Type: token.INT, Literal: "0x", Line: 1, Position: 1},
				{Type: token.IDENT, Literal: "G", Line: 1, Position: 3},
				{Type: token.EOF, Literal: "", Line: 1, Position: 4},
			},
		},
		{
			name:  "decimal exponent with no digits",
			input: "1e",
			expects: []token.Token{
				{Type: token.FLOAT, Literal: "1e", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 3},
			},
		},
		{
			name:  "decimal exponent with sign but no digits",
			input: "1e-",
			expects: []token.Token{
				{Type: token.FLOAT, Literal: "1e-", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 4},
			},
		},
		{
			name:  "hex float with no exponent digits",
			input: "0x1.8p",
			expects: []token.Token{
				{Type: token.FLOAT, Literal: "0x1.8p", Line: 1, Position: 1},
				{Type: token.EOF, Literal: "", Line: 1, Position: 7},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewFromString(tt.input)
			for i, want := range tt.expects {
				tok := l.NextToken()
				if diff := cmp.Diff(want, tok, cmpopts.IgnoreFields(token.Token{}, "Offset")); diff != "" {
					t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
				}
			}
		})
	}
}

func TestFastlyControlSyntaxes(t *testing.T) {
	t.Run("pragma syntax", func(t *testing.T) {
		input := "pragma optional_param geoip_opt_in true;"
		l := NewFromString(input)
		expects := []token.Token{
			{Type: token.PRAGMA, Literal: "pragma", Line: 1, Position: 1},
			{Type: token.IDENT, Literal: "optional_param", Line: 1, Position: 8},
			{Type: token.IDENT, Literal: "geoip_opt_in", Line: 1, Position: 23},
			{Type: token.TRUE, Literal: "true", Line: 1, Position: 36},
			{Type: token.SEMICOLON, Literal: ";", Line: 1, Position: 40},
			{Type: token.EOF, Literal: "", Line: 1, Position: 41},
		}
		for i, tt := range expects {
			tok := l.NextToken()

			if diff := cmp.Diff(tt, tok, cmpopts.IgnoreFields(token.Token{}, "Offset")); diff != "" {
				t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
			}
		}
	})

	t.Run("other control syntax of C!", func(t *testing.T) {
		input := "C!"
		l := NewFromString(input)
		expects := []token.Token{
			{Type: token.FASTLY_CONTROL, Literal: "C!", Line: 1, Position: 1},
			{Type: token.EOF, Literal: "", Line: 1, Position: 3},
		}
		for i, tt := range expects {
			tok := l.NextToken()

			if diff := cmp.Diff(tt, tok, cmpopts.IgnoreFields(token.Token{}, "Offset")); diff != "" {
				t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
			}
		}
	})

	t.Run("other control syntax of W!", func(t *testing.T) {
		input := "W!"
		l := NewFromString(input)
		expects := []token.Token{
			{Type: token.FASTLY_CONTROL, Literal: "W!", Line: 1, Position: 1},
			{Type: token.EOF, Literal: "", Line: 1, Position: 3},
		}
		for i, tt := range expects {
			tok := l.NextToken()

			if diff := cmp.Diff(tt, tok, cmpopts.IgnoreFields(token.Token{}, "Offset")); diff != "" {
				t.Errorf(`Tests[%d] failed, diff= %s`, i, diff)
			}
		}
	})
}
