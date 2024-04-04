package ast

import (
	"bytes"
)

type DeclareStatement struct {
	*Meta
	Name      *Ident
	ValueType *Ident
}

func (d *DeclareStatement) statement()     {}
func (d *DeclareStatement) GetMeta() *Meta { return d.Meta }
func (d *DeclareStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.LeadingComment())
	buf.WriteString(indent(d.Nest) + "declare ")
	buf.WriteString(d.InfixInlineComment())
	buf.WriteString("local ")
	buf.WriteString(d.Name.String())
	buf.WriteString(" ")
	buf.WriteString(d.ValueType.String() + ";")
	buf.WriteString(d.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
