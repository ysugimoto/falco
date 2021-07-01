package ast

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/token"
)

type DirectorDeclaration struct {
	Token        token.Token
	Name         *Ident
	DirectorType *Ident
	Properties   []Expression
	Comments     Comments
}

func (d *DirectorDeclaration) statement()            {}
func (d *DirectorDeclaration) GetComments() string   { return d.Comments.String() }
func (d *DirectorDeclaration) GetToken() token.Token { return d.Token }
func (d *DirectorDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.Comments.String())
	buf.WriteString("director ")
	buf.WriteString(d.Name.String())
	if d.DirectorType != nil {
		buf.WriteString(" " + d.DirectorType.String())
	}
	buf.WriteString(" {\n")
	for _, prop := range d.Properties {
		v := prop.String()
		buf.WriteString("  " + v)
		if !strings.HasSuffix(v, "}") {
			buf.WriteString(";")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("}\n")

	return buf.String()
}

type DirectorProperty struct {
	Token    token.Token
	Key      *Ident
	Value    Expression
	Comments Comments
}

func (d *DirectorProperty) expression()           {}
func (d *DirectorProperty) GetToken() token.Token { return d.Token }
func (d *DirectorProperty) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.Comments.String())
	buf.WriteString("." + d.Key.String())
	buf.WriteString(" = ")
	buf.WriteString(d.Value.String())

	return buf.String()
}

type DirectorBackendObject struct {
	Token    token.Token
	Values   []*DirectorProperty
	Comments Comments
}

func (d *DirectorBackendObject) expression()           {}
func (d *DirectorBackendObject) GetToken() token.Token { return d.Token }
func (d *DirectorBackendObject) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.Comments.String())
	buf.WriteString("{")
	for _, v := range d.Values {
		buf.WriteString(" " + v.String() + ";")
	}
	buf.WriteString(" }")

	return buf.String()
}
