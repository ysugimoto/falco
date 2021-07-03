package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type AddStatement struct {
	*Base
	Ident    *Ident
	Operator *Operator
	Value    Expression
}

func (a *AddStatement) statement()            {}
func (a *AddStatement) GetToken() token.Token { return a.Token }
func (a *AddStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(a.Leading.String(a.Nest))
	buf.WriteString(indent(a.Nest) + "add ")
	buf.WriteString(a.Ident.String())
	buf.WriteString(" " + a.Operator.String() + " ")
	buf.WriteString(a.Value.String())
	buf.WriteString(";")
	buf.WriteString(a.Trailing.String(a.Nest))
	buf.WriteString("\n")

	return buf.String()
}
