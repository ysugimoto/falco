package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type AddStatement struct {
	Token     token.Token
	Ident     *Ident
	Operator  *Operator
	Value     Expression
	NestLevel int
	Comments  Comments
}

func (a *AddStatement) statement()            {}
func (a *AddStatement) GetComments() string   { return a.Comments.String() }
func (a *AddStatement) GetToken() token.Token { return a.Token }
func (a *AddStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(a.Comments.String())
	buf.WriteString(indent(a.NestLevel) + "add ")
	buf.WriteString(a.Ident.String())
	buf.WriteString(" " + a.Operator.String() + " ")
	buf.WriteString(a.Value.String())
	buf.WriteString(";\n")

	return buf.String()
}
