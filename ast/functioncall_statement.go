package ast

import (
	"bytes"
)

type FunctionCallStatement struct {
	*Meta
	Function  *Ident
	Arguments []Expression
}

func (fc *FunctionCallStatement) ID() uint64     { return fc.Meta.ID }
func (fc *FunctionCallStatement) Statement()     {}
func (fc *FunctionCallStatement) GetMeta() *Meta { return fc.Meta }
func (fc *FunctionCallStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(fc.LeadingComment(lineFeed))
	buf.WriteString(fc.Function.String() + "(")
	for i, a := range fc.Arguments {
		buf.WriteString(a.String())
		if i != len(fc.Arguments)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString(")")
	if v := fc.InfixComment(inline); v != "" {
		buf.WriteString(paddingLeft(v))
	}
	buf.WriteString(";")
	buf.WriteString(fc.TrailingComment(inline))

	return buf.String()
}
