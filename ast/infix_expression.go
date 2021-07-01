package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type InfixExpression struct {
	Token    token.Token
	Left     Expression
	Operator string
	Right    Expression
}

func (i *InfixExpression) expression()           {}
func (i *InfixExpression) GetToken() token.Token { return i.Token }
func (i *InfixExpression) String() string {
	var buf bytes.Buffer

	buf.WriteString("(")
	buf.WriteString(i.Left.String())
	buf.WriteString(" " + i.Operator + " ")
	buf.WriteString(i.Right.String())
	buf.WriteString(")")

	return buf.String()
}
