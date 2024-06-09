package ast

import (
	"bytes"
)

type InfixExpression struct {
	*Meta
	Left     Expression
	Operator string
	Right    Expression
}

func (i *InfixExpression) ID() uint64     { return i.Meta.ID }
func (i *InfixExpression) Expression()    {}
func (i *InfixExpression) GetMeta() *Meta { return i.Meta }
func (i *InfixExpression) String() string {
	var buf bytes.Buffer

	buf.WriteString("(")
	buf.WriteString(i.Left.String())
	buf.WriteString(" " + i.Operator + " ")
	buf.WriteString(i.Right.String())
	buf.WriteString(")")

	return buf.String()
}
