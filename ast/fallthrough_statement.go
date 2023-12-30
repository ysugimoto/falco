package ast

import (
	"bytes"
)

type FallthroughStatement struct {
	*Meta
}

func (r *FallthroughStatement) statement()     {}
func (r *FallthroughStatement) GetMeta() *Meta { return r.Meta }
func (r *FallthroughStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment())
	buf.WriteString(indent(r.Nest) + "fallthrough;")
	buf.WriteString(r.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
