package ast

import (
	"bytes"
)

type IncludeStatement struct {
	*Meta
	Module *String
}

func (i *IncludeStatement) statement()     {}
func (i *IncludeStatement) GetMeta() *Meta { return i.Meta }
func (i *IncludeStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.LeadingComment())
	buf.WriteString(indent(i.Nest) + "include " + i.Module.String() + ";")
	buf.WriteString(i.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
