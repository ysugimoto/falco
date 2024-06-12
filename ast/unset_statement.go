package ast

import (
	"bytes"
)

type UnsetStatement struct {
	*Meta
	Ident *Ident
}

func (u *UnsetStatement) ID() uint64     { return u.Meta.ID }
func (u *UnsetStatement) Statement()     {}
func (u *UnsetStatement) GetMeta() *Meta { return u.Meta }
func (u *UnsetStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(u.LeadingComment(lineFeed))
	buf.WriteString(indent(u.Nest) + "unset")
	buf.WriteString(paddingLeft(u.Ident.String()))
	buf.WriteString(";")
	buf.WriteString(u.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
