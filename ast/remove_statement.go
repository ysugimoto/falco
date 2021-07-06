package ast

import (
	"bytes"
)

type RemoveStatement struct {
	*Meta
	Ident *Ident
}

func (r *RemoveStatement) statement()     {}
func (r *RemoveStatement) GetMeta() *Meta { return r.Meta }
func (r *RemoveStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment())
	buf.WriteString(indent(r.Nest) + "remove " + r.Ident.String() + ";")
	buf.WriteString(r.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
