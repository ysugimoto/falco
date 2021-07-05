package ast

import (
	"bytes"
)

type ReturnStatement struct {
	*Meta
	Ident *Ident
}

func (r *ReturnStatement) statement()     {}
func (r *ReturnStatement) GetMeta() *Meta { return r.Meta }
func (r *ReturnStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment())
	buf.WriteString(indent(r.Nest) + "return(" + r.Ident.String() + ");")
	buf.WriteString(r.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
