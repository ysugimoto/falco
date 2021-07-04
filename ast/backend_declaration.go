package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type BackendDeclaration struct {
	*Meta
	Name       *Ident
	Properties []*BackendProperty
}

func (b *BackendDeclaration) statement()            {}
func (b *BackendDeclaration) expression()           {}
func (b *BackendDeclaration) GetToken() token.Token { return b.Token }
func (b *BackendDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(b.LeadingComment())
	buf.WriteString("backend ")
	buf.WriteString(b.Name.String())
	buf.WriteString(" {\n")
	for _, prop := range b.Properties {
		buf.WriteString(prop.String() + "\n")
	}
	buf.WriteString(b.InfixComment())
	buf.WriteString("}")
	buf.WriteString(b.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}

type BackendProperty struct {
	*Meta
	Key   *Ident
	Value Expression
}

func (p *BackendProperty) expression()           {}
func (p *BackendProperty) GetToken() token.Token { return p.Token }
func (p *BackendProperty) String() string {
	var buf bytes.Buffer

	buf.WriteString(p.LeadingComment())
	buf.WriteString(indent(p.Nest) + "." + p.Key.String())
	buf.WriteString(" = ")
	buf.WriteString(p.Value.String())
	if _, ok := p.Value.(*BackendProbeObject); !ok {
		buf.WriteString(";")
	}
	buf.WriteString(p.TrailingComment())

	return buf.String()
}

type BackendProbeObject struct {
	*Meta
	Values []*BackendProperty
}

func (o *BackendProbeObject) expression()           {}
func (o *BackendProbeObject) GetToken() token.Token { return o.Token }
func (o *BackendProbeObject) String() string {
	var buf bytes.Buffer

	buf.WriteString("{\n")
	for _, p := range o.Values {
		buf.WriteString(p.LeadingComment())
		buf.WriteString(indent(p.Nest) + "." + p.Key.String())
		buf.WriteString(" = ")
		buf.WriteString(p.Value.String())
		buf.WriteString(";")
		buf.WriteString(p.TrailingComment())
		buf.WriteString("\n")
	}
	buf.WriteString(o.InfixComment())
	buf.WriteString(indent(o.Nest) + "}")

	return buf.String()
}
