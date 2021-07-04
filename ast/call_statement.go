package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type CallStatement struct {
	*Meta
	Subroutine *Ident
}

func (c *CallStatement) statement()            {}
func (c *CallStatement) GetToken() token.Token { return c.Token }
func (c *CallStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(c.LeadingComment())
	buf.WriteString(indent(c.Nest) + "call " + c.Subroutine.String() + ";")
	buf.WriteString(c.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
