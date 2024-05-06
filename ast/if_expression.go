package ast

import (
	"bytes"
)

type IfExpression struct {
	*Meta
	Condition   Expression
	Consequence Expression
	Alternative Expression
}

func (i *IfExpression) Expression()    {}
func (i *IfExpression) GetMeta() *Meta { return i.Meta }
func (i *IfExpression) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.LeadingComment(inline))
	buf.WriteString("if")
	buf.WriteString(i.InfixComment(inline))
	buf.WriteString("(")
	buf.WriteString(i.Condition.String())
	buf.WriteString(", ")
	buf.WriteString(i.Consequence.String())
	buf.WriteString(", ")
	buf.WriteString(i.Alternative.String())
	buf.WriteString(")")
	buf.WriteString(i.TrailingComment(inline))

	return buf.String()
}
