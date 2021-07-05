package ast

import (
	"bytes"
)

type UnsetStatement struct {
	*Meta
	Ident *Ident
}

func (u *UnsetStatement) statement()     {}
func (u *UnsetStatement) GetMeta() *Meta { return u.Meta }
func (u *UnsetStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(u.LeadingComment())
	buf.WriteString(indent(u.Nest) + "unset " + u.Ident.String() + ";")
	buf.WriteString(u.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
