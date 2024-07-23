package ast

import (
	"bytes"
)

type PostfixExpression struct {
	*Meta
	Left     Expression
	Operator string
}

func (i *PostfixExpression) ID() uint64     { return i.Meta.ID }
func (i *PostfixExpression) Expression()    {}
func (i *PostfixExpression) GetMeta() *Meta { return i.Meta }
func (i *PostfixExpression) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.Left.String())
	buf.WriteString(i.Operator)
	buf.WriteString(paddingLeft(i.TrailingComment(inline)))

	return buf.String()
}
