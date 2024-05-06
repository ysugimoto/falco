package ast

import (
	"bytes"
)

type FunctionCallExpression struct {
	*Meta
	Function  *Ident
	Arguments []Expression
}

func (f *FunctionCallExpression) Expression()    {}
func (f *FunctionCallExpression) GetMeta() *Meta { return f.Meta }
func (f *FunctionCallExpression) String() string {
	var buf bytes.Buffer

	buf.WriteString(f.LeadingComment(inline))
	buf.WriteString(f.Function.String() + "(")
	for i, a := range f.Arguments {
		buf.WriteString(a.String())
		if i != len(f.Arguments)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString(")")
	buf.WriteString(f.TrailingComment(inline))

	return buf.String()
}
