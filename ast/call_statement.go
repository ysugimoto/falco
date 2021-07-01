package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type CallStatement struct {
	Token      token.Token
	Subroutine *Ident
	NestLevel  int
	Comments   Comments
}

func (c *CallStatement) statement()            {}
func (c *CallStatement) GetComments() string   { return c.Comments.String() }
func (c *CallStatement) GetToken() token.Token { return c.Token }
func (c *CallStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(c.Comments.String())
	buf.WriteString(indent(c.NestLevel) + "call " + c.Subroutine.String() + ";\n")

	return buf.String()
}
