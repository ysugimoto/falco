package ast

import (
	"bytes"
)

type PrefixExpression struct {
	*Meta
	Operator string
	Right    Expression
}

func (p *PrefixExpression) expression()    {}
func (p *PrefixExpression) GetMeta() *Meta { return p.Meta }
func (p *PrefixExpression) String() string {
	var buf bytes.Buffer

	buf.WriteString("(")
	buf.WriteString(p.LeadingComment(inline))
	buf.WriteString(p.Operator)
	buf.WriteString(p.Right.String())
	buf.WriteString(")")

	return buf.String()
}
