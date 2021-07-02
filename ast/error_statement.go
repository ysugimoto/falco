package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type ErrorStatement struct {
	Token     token.Token
	Code      Expression
	Argument  Expression
	NestLevel int
	Comments  Comments
}

func (e *ErrorStatement) statement()            {}
func (e *ErrorStatement) GetComments() string   { return e.Comments.String() }
func (e *ErrorStatement) GetToken() token.Token { return e.Token }
func (e *ErrorStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(e.Comments.String())
	buf.WriteString(indent(e.NestLevel) + "error " + e.Code.String())
	if e.Argument != nil {
		buf.WriteString(" " + e.Argument.String())
	}
	buf.WriteString(";\n")

	return buf.String()
}
