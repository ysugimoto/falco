package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type ReturnStatement struct {
	*Meta
	Ident *Ident
}

func (r *ReturnStatement) statement()            {}
func (r *ReturnStatement) GetToken() token.Token { return r.Token }
func (r *ReturnStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment())
	buf.WriteString(indent(r.Nest) + "return(" + r.Ident.String() + ");")
	buf.WriteString(r.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
