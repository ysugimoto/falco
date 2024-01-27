package ast

import (
	"bytes"
)

type BreakStatement struct {
	*Meta
}

func (r *BreakStatement) statement()     {}
func (r *BreakStatement) GetMeta() *Meta { return r.Meta }
func (r *BreakStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment())
	buf.WriteString(indent(r.Nest) + "break;")
	buf.WriteString(r.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
