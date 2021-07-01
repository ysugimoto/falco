package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type UnsetStatement struct {
	Token     token.Token
	Ident     *Ident
	NestLevel int
	Comments  Comments
}

func (u *UnsetStatement) statement()            {}
func (u *UnsetStatement) GetComments() string   { return u.Comments.String() }
func (u *UnsetStatement) GetToken() token.Token { return u.Token }
func (u *UnsetStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(u.Comments.String())
	buf.WriteString(indent(u.NestLevel) + "unset ")
	buf.WriteString(u.Ident.String() + ";\n")

	return buf.String()
}
