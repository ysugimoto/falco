package ast

import (
	"bytes"
)

type EsiStatement struct {
	*Meta
}

func (e *EsiStatement) ID() uint64     { return e.Meta.ID }
func (e *EsiStatement) Statement()     {}
func (e *EsiStatement) GetMeta() *Meta { return e.Meta }
func (e *EsiStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(e.LeadingComment(lineFeed))
	buf.WriteString(indent(e.Nest) + "esi")
	buf.WriteString(paddingLeft(e.InfixComment(inline)))
	buf.WriteString(";")
	buf.WriteString(e.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
