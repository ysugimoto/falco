package ast

import (
	"bytes"
)

type DeclareStatement struct {
	*Meta
	Name      *Ident
	ValueType *Ident
}

func (d *DeclareStatement) Statement()     {}
func (d *DeclareStatement) GetMeta() *Meta { return d.Meta }
func (d *DeclareStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.LeadingComment(lineFeed))
	buf.WriteString(indent(d.Nest))
	buf.WriteString("declare")
	buf.WriteString(paddingLeft(d.InfixComment(inline)))
	buf.WriteString(" local")
	buf.WriteString(padding(d.Name.String()))
	buf.WriteString(d.ValueType.String() + ";")
	buf.WriteString(d.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
