package ast

import (
	"bytes"
)

type RemoveStatement struct {
	*Meta
	Ident *Ident
}

func (r *RemoveStatement) ID() uint64     { return r.Meta.ID }
func (r *RemoveStatement) Statement()     {}
func (r *RemoveStatement) GetMeta() *Meta { return r.Meta }
func (r *RemoveStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment(lineFeed))
	buf.WriteString(indent(r.Nest) + "remove" + paddingLeft(r.Ident.String()) + ";")
	buf.WriteString(r.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
