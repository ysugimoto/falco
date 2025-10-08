package ast

import (
	"bytes"
)

type FallthroughStatement struct {
	*Meta
}

func (r *FallthroughStatement) ID() uint64     { return r.Meta.ID }
func (r *FallthroughStatement) Statement()     {}
func (r *FallthroughStatement) GetMeta() *Meta { return r.Meta }
func (r *FallthroughStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment(lineFeed))
	buf.WriteString(indent(r.Nest) + "fallthrough")
	buf.WriteString(paddingLeft(r.InfixComment(inline)))
	buf.WriteString(";")
	buf.WriteString(r.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
