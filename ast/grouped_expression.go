package ast

import (
	"bytes"
)

type GroupedExpression struct {
	*Meta
	Right Expression
}

func (g *GroupedExpression) expression()    {}
func (g *GroupedExpression) GetMeta() *Meta { return g.Meta }
func (g *GroupedExpression) String() string {
	var buf bytes.Buffer

	buf.WriteString("(")
	buf.WriteString(g.Right.String())
	buf.WriteString(")")

	return buf.String()
}
