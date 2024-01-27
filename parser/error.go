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
	var file string
	if e.Token.File != "" {
		file = " at " + e.Token.File
	}
	return fmt.Sprintf(
		"Parse Error: %s%s, line: %d, position: %d",
		e.Message, file, e.Token.Line, e.Token.Position,
	)
}

func (e *ParseError) ErrorToken() token.Token {
	return e.Token
}

func MissingSemicolon(m *ast.Meta) *ParseError {
	return &ParseError{
		Token:   m.Token,
		Message: "Missing semicolon",
	}
}

func MissingColon(m *ast.Meta) *ParseError {
	return &ParseError{
		Token:   m.Token,
		Message: "Missing colon",
	}
}

func UnexpectedToken(m *ast.Meta, expects ...string) *ParseError {
	message := fmt.Sprintf(`Unexpected token "%s"`, m.Token.Literal)
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
		Message: "Undefined prefix expression for " + m.Token.Literal,
	}
}

func TypeConversionError(m *ast.Meta, tt string) *ParseError {
	return &ParseError{
		Token:   m.Token,
		Message: fmt.Sprintf("Failed type conversion for token %s to %s ", m.Token.Literal, tt),
	}
}

func DuplicateCase(m *ast.Meta) *ParseError {
	return &ParseError{
		Token:   m.Token,
		Message: "Duplicate case label: " + m.Token.Literal,
	}
}

func MultipleDefaults(m *ast.Meta) *ParseError {
	return &ParseError{
		Token:   m.Token,
		Message: "Multiple default cases",
	}
}

func FinalFallthrough(m *ast.Meta) *ParseError {
	return &ParseError{
		Token:   m.Token,
		Message: "Final case cannot have fallthrough",
	}
}

func EmptySwitch(m *ast.Meta) *ParseError {
	return &ParseError{
		Token:   m.Token,
		Message: "Switch must have at least one case",
	}
}
