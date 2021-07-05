package ast

import (
	"bytes"
)

type DirectorDeclaration struct {
	*Meta
	Name         *Ident
	DirectorType *Ident
	Properties   []Expression
}

func (d *DirectorDeclaration) statement()     {}
func (d *DirectorDeclaration) GetMeta() *Meta { return d.Meta }
func (d *DirectorDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.LeadingComment())
	buf.WriteString("director ")
	buf.WriteString(d.Name.String())
	if d.DirectorType != nil {
		buf.WriteString(" " + d.DirectorType.String())
	}
	buf.WriteString(" {\n")
	for _, prop := range d.Properties {
		buf.WriteString(prop.String())
	}
	buf.WriteString("}")
	buf.WriteString(d.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}

type DirectorProperty struct {
	*Meta
	Key   *Ident
	Value Expression
}

func (d *DirectorProperty) expression()    {}
func (d *DirectorProperty) GetMeta() *Meta { return d.Meta }
func (d *DirectorProperty) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.LeadingComment())
	buf.WriteString(indent(d.Nest) + "." + d.Key.String())
	buf.WriteString(" = ")
	buf.WriteString(d.Value.String())
	buf.WriteString(";")
	buf.WriteString(d.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}

type DirectorBackendObject struct {
	*Meta
	Values []*DirectorProperty
}

func (d *DirectorBackendObject) expression()    {}
func (d *DirectorBackendObject) GetMeta() *Meta { return d.Meta }
func (d *DirectorBackendObject) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.LeadingComment())
	buf.WriteString(indent(d.Nest) + "{")
	for _, v := range d.Values {
		buf.WriteString(" ." + v.Key.String())
		buf.WriteString(" = ")
		buf.WriteString(v.Value.String())
		buf.WriteString(";")
	}
	buf.WriteString(" }")
	buf.WriteString(d.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
