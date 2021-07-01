package parser

import (
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/token"
)

type ParseError struct {
	Token   token.Token
	Message string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf(
		"Parse Error: %s, line: %d, position: %d",
		e.Message, e.Token.Line, e.Token.Position,
	)
}

func (e *ParseError) ErrorToken() token.Token {
	return e.Token
}

func MissingSemicolon(t token.Token) *ParseError {
	return &ParseError{
		Token:   t,
		Message: "Missing semilocon",
	}
}

func UnexpectedToken(t token.Token, expects ...string) *ParseError {
	m := fmt.Sprintf(`Unexpected token "%s" found`, t.Literal)
	if len(expects) > 0 {
		m += fmt.Sprintf(`, expects %s`, strings.Join(expects, " or "))
	}
	return &ParseError{
		Token:   t,
		Message: m,
	}
}

func UndefinedPrefix(t token.Token) *ParseError {
	return &ParseError{
		Token:   t,
		Message: "Undefined prefix expression parse of " + t.Literal,
	}
}

func TypeConversionError(t token.Token, tt string) *ParseError {
	return &ParseError{
		Token:   t,
		Message: fmt.Sprintf("Failed type conversion token %s to %s ", t.Literal, tt),
	}
}
