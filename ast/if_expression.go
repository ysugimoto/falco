package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type IfExpression struct {
	*Meta
	Condition   Expression
	Consequence Expression
	Alternative Expression
}

func (i *IfExpression) expression()           {}
func (i *IfExpression) GetToken() token.Token { return i.Token }
func (i *IfExpression) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.LeadingInlineComment())
	buf.WriteString("if(")
	buf.WriteString(i.Condition.String())
	buf.WriteString(", ")
	buf.WriteString(i.Consequence.String())
	buf.WriteString(", ")
	buf.WriteString(i.Alternative.String())
	buf.WriteString(")")
	buf.WriteString(i.TrailingComment())

	return buf.String()
}
