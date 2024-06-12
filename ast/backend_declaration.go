package ast

import (
	"bytes"
)

type BackendDeclaration struct {
	*Meta
	Name       *Ident
	Properties []*BackendProperty
}

func (b *BackendDeclaration) ID() uint64     { return b.Meta.ID }
func (b *BackendDeclaration) Statement()     {}
func (b *BackendDeclaration) Expression()    {}
func (b *BackendDeclaration) GetMeta() *Meta { return b.Meta }
func (b *BackendDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(b.LeadingComment(lineFeed))
	buf.WriteString("backend ")
	buf.WriteString(b.Name.String())
	buf.WriteString(" {\n")
	for _, prop := range b.Properties {
		buf.WriteString(prop.String() + "\n")
	}
	buf.WriteString(b.InfixComment(lineFeed))
	buf.WriteString("}")
	buf.WriteString(b.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}

type BackendProperty struct {
	*Meta
	Key   *Ident
	Value Expression
}

func (b *BackendProperty) ID() uint64     { return b.Meta.ID }
func (p *BackendProperty) Expression()    {}
func (p *BackendProperty) GetMeta() *Meta { return p.Meta }
func (p *BackendProperty) String() string {
	var buf bytes.Buffer

	buf.WriteString(p.LeadingComment(lineFeed))
	buf.WriteString(indent(p.Nest) + "." + p.Key.String())
	buf.WriteString(" = ")
	buf.WriteString(p.Value.String())
	if _, ok := p.Value.(*BackendProbeObject); !ok {
		buf.WriteString(";")
	}
	buf.WriteString(p.TrailingComment(inline))

	return buf.String()
}

type BackendProbeObject struct {
	*Meta
	Values []*BackendProperty
}

func (o *BackendProbeObject) ID() uint64     { return o.Meta.ID }
func (o *BackendProbeObject) Expression()    {}
func (o *BackendProbeObject) GetMeta() *Meta { return o.Meta }
func (o *BackendProbeObject) String() string {
	var buf bytes.Buffer

	buf.WriteString("{\n")
	for _, p := range o.Values {
		buf.WriteString(p.LeadingComment(lineFeed))
		buf.WriteString(indent(p.Nest) + "." + p.Key.String())
		buf.WriteString(" = ")
		buf.WriteString(p.Value.String())
		buf.WriteString(";")
		buf.WriteString(p.TrailingComment(inline))
		buf.WriteString("\n")
	}
	buf.WriteString(o.InfixComment(lineFeed))
	buf.WriteString(indent(o.Nest) + "}")

	return buf.String()
}
