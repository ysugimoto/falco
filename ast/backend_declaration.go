package ast

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/token"
)

type BackendDeclaration struct {
	Token      token.Token
	Name       *Ident
	Properties []*BackendProperty
	Comments   Comments
}

func (b *BackendDeclaration) statement()            {}
func (b *BackendDeclaration) expression()           {}
func (b *BackendDeclaration) GetComments() string   { return b.Comments.String() }
func (b *BackendDeclaration) GetToken() token.Token { return b.Token }
func (b *BackendDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(b.Comments.String())
	buf.WriteString("backend ")
	buf.WriteString(b.Name.String())
	buf.WriteString(" {\n")
	for _, props := range b.Properties {
		v := props.String()
		buf.WriteString("  " + v + "\n")
	}
	buf.WriteString("}\n")

	return buf.String()
}

type BackendProperty struct {
	Token    token.Token
	Key      *Ident
	Value    Expression
	Comments Comments
}

func (p *BackendProperty) expression()           {}
func (p *BackendProperty) GetToken() token.Token { return p.Token }
func (p *BackendProperty) String() string {
	var buf bytes.Buffer

	buf.WriteString(p.Comments.String())
	buf.WriteString("." + p.Key.String())
	buf.WriteString(" = ")
	v := p.Value.String()
	if !strings.HasSuffix(v, "}") {
		buf.WriteString(";")
	}

	return buf.String()
}

type BackendProbeObject struct {
	Token  token.Token
	Values []*BackendProperty
}

func (o *BackendProbeObject) expression()           {}
func (o *BackendProbeObject) GetToken() token.Token { return o.Token }
func (o *BackendProbeObject) String() string {
	var buf bytes.Buffer

	buf.WriteString("{\n")
	for _, p := range o.Values {
		buf.WriteString("    " + p.String() + ";\n")
	}
	buf.WriteString("  }")

	return buf.String()
}
