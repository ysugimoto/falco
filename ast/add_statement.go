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

func (a *AddStatement) ID() uint64     { return a.Meta.ID }
func (a *AddStatement) Statement()     {}
func (a *AddStatement) GetMeta() *Meta { return a.Meta }
func (a *AddStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(a.LeadingComment(lineFeed))
	buf.WriteString(indent(a.Nest) + "add")
	buf.WriteString(padding(a.Ident.String()))
	buf.WriteString(a.Operator.String())
	buf.WriteString(paddingLeft(a.Value.String()))
	buf.WriteString(";")
	buf.WriteString(a.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
