package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type TableDeclaration struct {
	Token      token.Token
	Name       *Ident
	ValueType  *Ident
	Properties []*TableProperty
	Comments   Comments
}

func (t *TableDeclaration) statement()            {}
func (t *TableDeclaration) GetComments() string   { return t.Comments.String() }
func (t *TableDeclaration) GetToken() token.Token { return t.Token }
func (t *TableDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(t.Comments.String())
	buf.WriteString("table ")
	buf.WriteString(t.Name.String())
	if t.ValueType != nil {
		buf.WriteString(" " + t.ValueType.String())
	}
	buf.WriteString(" {\n")
	for _, props := range t.Properties {
		buf.WriteString("  " + props.String() + "\n")
	}
	buf.WriteString("}\n")

	return buf.String()
}

type TableProperty struct {
	Token         token.Token
	Key           *String
	Value         Expression
	Comments      Comments
	AfterComments Comments
}

func (t *TableProperty) String() string {
	var buf bytes.Buffer

	buf.WriteString(t.Comments.String())
	buf.WriteString(t.Key.String())
	buf.WriteString(": ")
	buf.WriteString(t.Value.String())
	buf.WriteString(",")
	buf.WriteString(t.AfterComments.String())

	return buf.String()
}
