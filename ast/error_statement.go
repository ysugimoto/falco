package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type ErrorStatement struct {
	*Meta
	Code     Expression
	Argument Expression
}

func (e *ErrorStatement) statement()            {}
func (e *ErrorStatement) GetToken() token.Token { return e.Token }
func (e *ErrorStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(e.LeadingComment())
	buf.WriteString(indent(e.Nest) + "error " + e.Code.String())
	if e.Argument != nil {
		buf.WriteString(" " + e.Argument.String())
	}
	buf.WriteString(";")
	buf.WriteString(e.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
