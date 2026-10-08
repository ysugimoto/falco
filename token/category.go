package token

// Category maps a token type to a coarse semantic category for syntax
// highlighting. It is shared by the cmd/wasm and cmd/falco-component builds so
// they cannot diverge.
func Category(tt TokenType) string {
	switch tt {
	// Keywords
	case ACL, BACKEND, DIRECTOR, TABLE, SUBROUTINE,
		ADD, CALL, DECLARE, ERROR, ESI,
		INCLUDE, IMPORT, LOG, REMOVE, RESTART,
		RETURN, SET, SYNTHETIC, SYNTHETIC_BASE64, UNSET,
		IF, ELSE, ELSEIF, ELSIF,
		PENALTYBOX, RATECOUNTER, GOTO,
		SWITCH, CASE, DEFAULT, BREAK, FALLTHROUGH,
		PRAGMA:
		return "keyword"

	// Strings
	case STRING, OPEN_LONG_STRING, CLOSE_LONG_STRING:
		return "string"

	// Numbers
	case INT, FLOAT, RTIME:
		return "number"

	// Booleans
	case TRUE, FALSE:
		return "boolean"

	// Identifiers
	case IDENT:
		return "variable"

	// Operators
	case EQUAL, NOT_EQUAL, REGEX_MATCH, NOT_REGEX_MATCH,
		GREATER_THAN, LESS_THAN, GREATER_THAN_EQUAL, LESS_THAN_EQUAL,
		AND, OR, NOT,
		ASSIGN, ADDITION, SUBTRACTION, MULTIPLICATION,
		DIVISION, REMAINDER,
		BITWISE_OR, BITWISE_AND, BITWISE_XOR,
		LEFT_SHIFT, RIGHT_SHIFT, LEFT_ROTATE, RIGHT_ROTATE,
		LOGICAL_AND, LOGICAL_OR,
		PLUS, MINUS, SLASH, PERCENT:
		return "operator"

	// Comments
	case COMMENT:
		return "comment"

	// Punctuation
	case LEFT_BRACE, RIGHT_BRACE, LEFT_PAREN, RIGHT_PAREN,
		LEFT_BRACKET, RIGHT_BRACKET, COMMA, SEMICOLON,
		DOT, COLON:
		return "punctuation"

	// Control
	case FASTLY_CONTROL:
		return "control"

	default:
		return "text"
	}
}
