package ast

import (
	"bytes"
	"strings"
)

type CallStatement struct {
	*Meta
	Subroutine *Ident
	Arguments  []Expression
}

func (c *CallStatement) ID() uint64     { return c.Meta.ID }
func (c *CallStatement) Statement()     {}
func (c *CallStatement) GetMeta() *Meta { return c.Meta }
func (c *CallStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(c.LeadingComment(lineFeed))
	buf.WriteString(indent(c.Nest) + "call " + c.Subroutine.String())

	if len(c.Arguments) > 0 {
		buf.WriteString("(")
		args := make([]string, len(c.Arguments))
		for i, arg := range c.Arguments {
			args[i] = arg.String()
		}
		buf.WriteString(strings.Join(args, ", "))
		buf.WriteString(")")
	}

	buf.WriteString(";")
	buf.WriteString(c.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
