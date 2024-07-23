package ast

import (
	"bytes"
)

type CallStatement struct {
	*Meta
	Subroutine *Ident
}

func (c *CallStatement) ID() uint64     { return c.Meta.ID }
func (c *CallStatement) Statement()     {}
func (c *CallStatement) GetMeta() *Meta { return c.Meta }
func (c *CallStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(c.LeadingComment(lineFeed))
	buf.WriteString(indent(c.Nest) + "call " + c.Subroutine.String() + ";")
	buf.WriteString(c.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
