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

func (d *DirectorDeclaration) ID() uint64     { return d.Meta.ID }
func (d *DirectorDeclaration) Statement()     {}
func (d *DirectorDeclaration) GetMeta() *Meta { return d.Meta }
func (d *DirectorDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.LeadingComment(lineFeed))
	buf.WriteString("director ")
	buf.WriteString(d.Name.String())
	if d.DirectorType != nil {
		buf.WriteString(" " + d.DirectorType.String())
	}
	buf.WriteString(" {\n")
	for _, prop := range d.Properties {
		buf.WriteString(prop.String())
	}
	if v := d.InfixComment(lineFeed); v != "" {
		buf.WriteString("  " + v)
	}
	buf.WriteString("}")
	buf.WriteString(d.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}

type DirectorProperty struct {
	*Meta
	Key   *Ident
	Value Expression
}

func (d *DirectorProperty) ID() uint64     { return d.Meta.ID }
func (d *DirectorProperty) Expression()    {}
func (d *DirectorProperty) GetMeta() *Meta { return d.Meta }
func (d *DirectorProperty) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.LeadingComment(lineFeed))
	buf.WriteString(indent(d.Nest) + "." + d.Key.String())
	buf.WriteString(" = ")
	buf.WriteString(d.Value.String())
	buf.WriteString(";")
	buf.WriteString(d.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}

type DirectorBackendObject struct {
	*Meta
	Values []*DirectorProperty
}

func (d *DirectorBackendObject) ID() uint64     { return d.Meta.ID }
func (d *DirectorBackendObject) Expression()    {}
func (d *DirectorBackendObject) GetMeta() *Meta { return d.Meta }
func (d *DirectorBackendObject) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.LeadingComment(lineFeed))
	buf.WriteString(indent(d.Nest) + "{")
	for _, v := range d.Values {
		buf.WriteString(paddingLeft(v.Key.LeadingComment(inline)))
		buf.WriteString(" .")
		buf.WriteString(paddingRight(v.Key.Value))
		buf.WriteString(paddingRight(v.Key.TrailingComment(inline)))
		buf.WriteString("=")
		buf.WriteString(paddingLeft(v.Value.String()))
		buf.WriteString(";")
		buf.WriteString(v.TrailingComment(inline))
	}
	if v := d.InfixComment(inline); v != "" {
		buf.WriteString(paddingLeft(v))
	}
	buf.WriteString(" }")
	buf.WriteString(d.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
