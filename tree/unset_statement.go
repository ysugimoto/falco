package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type UnsetStatement struct {
	*Meta
	Ident *Ident
}

func (u *UnsetStatement) statement()            {}
func (u *UnsetStatement) GetToken() token.Token { return u.Token }
func (u *UnsetStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(u.LeadingComment())
	buf.WriteString(indent(u.Nest) + "unset " + u.Ident.String() + ";")
	buf.WriteString(u.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
