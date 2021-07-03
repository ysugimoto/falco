package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type DeclareStatement struct {
	*Meta
	Name      *Ident
	ValueType *Ident
}

func (d *DeclareStatement) statement()            {}
func (d *DeclareStatement) GetToken() token.Token { return d.Token }
func (d *DeclareStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.LeadingComment())
	buf.WriteString(indent(d.Nest) + "declare local ")
	buf.WriteString(d.Name.String())
	buf.WriteString(" ")
	buf.WriteString(d.ValueType.String() + ";")
	buf.WriteString(d.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
