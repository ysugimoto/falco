package formatter

import (
	"fmt"

	"github.com/ysugimoto/falco/token"
)

type FormatError struct {
	token   token.Token
	message string
}

func (f *FormatError) Error() string {
	return f.message
}

// shorthand functions
func UnexpectedToken(actual token.Token, expects token.TokenType) *FormatError {
	return &FormatError{
		token:   actual,
		message: fmt.Sprintf(`Unexpected token found. Expects "%s" but found "%s"`, expects, actual.Type),
	}
}

func UnexpectedEOF(actual token.Token) *FormatError {
	return &FormatError{
		token:   actual,
		message: "Unexpected EOF",
	}
}
