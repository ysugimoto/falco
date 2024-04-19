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

	buf.WriteString(r.LeadingComment(lineFeed))
	buf.WriteString(indent(r.Nest) + "break")
	buf.WriteString(paddingLeft(r.InfixComment(inline)))
	buf.WriteString(";")
	buf.WriteString(r.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
