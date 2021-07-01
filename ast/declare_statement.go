package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type DeclareStatement struct {
	Token     token.Token
	Name      *Ident
	ValueType *Ident
	NestLevel int
	Comments  Comments
}

func (d *DeclareStatement) statement()            {}
func (d *DeclareStatement) GetComments() string   { return d.Comments.String() }
func (d *DeclareStatement) GetToken() token.Token { return d.Token }
func (d *DeclareStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(d.Comments.String())
	buf.WriteString(indent(d.NestLevel) + "declare local ")
	buf.WriteString(d.Name.String())
	buf.WriteString(" ")
	buf.WriteString(d.ValueType.String() + ";\n")

	return buf.String()
}
