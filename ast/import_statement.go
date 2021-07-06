package ast

import (
	"bytes"
)

type ImportStatement struct {
	*Meta
	Name *Ident
}

func (i *ImportStatement) statement()     {}
func (i *ImportStatement) GetMeta() *Meta { return i.Meta }
func (i *ImportStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(i.LeadingComment())
	buf.WriteString(indent(i.Nest) + "import " + i.Name.String() + ";")
	buf.WriteString(i.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
