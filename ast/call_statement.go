package ast

import (
	"bytes"
)

type CallStatement struct {
	*Meta
	Subroutine *Ident
}

func (c *CallStatement) statement()     {}
func (c *CallStatement) GetMeta() *Meta { return c.Meta }
func (c *CallStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(c.LeadingComment(lineFeed))
	buf.WriteString(indent(c.Nest) + "call " + c.Subroutine.String() + ";")
	buf.WriteString(c.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
