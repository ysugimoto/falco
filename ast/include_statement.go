package ast

import (
	"bytes"
)

type IncludeStatement struct {
	*Meta
	Module *String
}

func (i *IncludeStatement) ID() uint64     { return i.Meta.ID }
func (i *IncludeStatement) Statement()     {}
func (i *IncludeStatement) GetMeta() *Meta { return i.Meta }
func (i *IncludeStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.LeadingComment(lineFeed))
	buf.WriteString(indent(i.Nest) + "include" + paddingLeft(i.Module.String()) + ";")
	buf.WriteString(i.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
