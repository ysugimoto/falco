package ast

import (
	"bytes"
)

type AddStatement struct {
	*Meta
	Ident    *Ident
	Operator *Operator
	Value    Expression
}

func (a *AddStatement) statement()     {}
func (a *AddStatement) GetMeta() *Meta { return a.Meta }
func (a *AddStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(a.LeadingComment())
	buf.WriteString(indent(a.Nest) + "add ")
	buf.WriteString(a.Ident.String())
	buf.WriteString(" " + a.Operator.String() + " ")
	buf.WriteString(a.Value.String())
	buf.WriteString(";")
	buf.WriteString(a.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
