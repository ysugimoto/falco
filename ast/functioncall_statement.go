package ast

import (
	"bytes"
)

type FunctionCallStatement struct {
	*Meta
	Function                   *Ident
	Arguments                  []Expression
	ParenthesisTrailingComment Comments
}

func (fc *FunctionCallStatement) statement()     {}
func (fc *FunctionCallStatement) GetMeta() *Meta { return fc.Meta }
func (fc *FunctionCallStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(fc.LeadingInlineComment())
	buf.WriteString(fc.Function.String() + "(")
	for i, a := range fc.Arguments {
		buf.WriteString(a.String())
		if i != len(fc.Arguments)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString(")")
	if v := fc.ParenthesisTrailingComment.String(); v != "" {
		buf.WriteString(" " + v)
	}
	buf.WriteString(";")
	buf.WriteString(fc.TrailingComment())

	return buf.String()
}
