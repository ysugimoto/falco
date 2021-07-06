package parser

import (
	"fmt"
	"strings"

	"github.com/ysugimoto/falco/ast"
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

func MissingSemicolon(m *ast.Meta) *ParseError {
	return &ParseError{
		Token:   m.Token,
		Message: "Missing semilocon",
	}
}

func UnexpectedToken(m *ast.Meta, expects ...string) *ParseError {
	message := fmt.Sprintf(`Unexpected token "%s" found`, m.Token.Literal)
	if len(expects) > 0 {
		message += fmt.Sprintf(`, expects %s`, strings.Join(expects, " or "))
	}
	return &ParseError{
		Token:   m.Token,
		Message: message,
	}
}

func UndefinedPrefix(m *ast.Meta) *ParseError {
	return &ParseError{
		Token:   m.Token,
		Message: "Undefined prefix expression parse of " + m.Token.Literal,
	}
}

func TypeConversionError(m *ast.Meta, tt string) *ParseError {
	return &ParseError{
		Token:   m.Token,
		Message: fmt.Sprintf("Failed type conversion token %s to %s ", m.Token.Literal, tt),
	}
}
