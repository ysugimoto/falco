package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type GroupedExpression struct {
	*Meta
	Right Expression
}

func (g *GroupedExpression) expression()           {}
func (g *GroupedExpression) GetToken() token.Token { return g.Token }
func (g *GroupedExpression) String() string {
	var buf bytes.Buffer

	buf.WriteString("(")
	buf.WriteString(g.Right.String())
	buf.WriteString(")")

	return buf.String()
}
