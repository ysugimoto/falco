package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type PrefixExpression struct {
	*Meta
	Operator string
	Right    Expression
}

func (p *PrefixExpression) expression()           {}
func (p *PrefixExpression) GetToken() token.Token { return p.Token }
func (p *PrefixExpression) String() string {
	var buf bytes.Buffer

	buf.WriteString("(")
	buf.WriteString(p.LeadingInlineComment())
	buf.WriteString(p.Operator)
	buf.WriteString(p.Right.String())
	buf.WriteString(")")

	return buf.String()
}
