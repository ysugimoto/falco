package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type BlockStatement struct {
	Token      token.Token
	Statements []Statement
	NestLevel  int
	Comments   Comments
}

func (b *BlockStatement) statement()            {}
func (b *BlockStatement) GetComments() string   { return b.Comments.String() }
func (b *BlockStatement) GetToken() token.Token { return b.Token }
func (b *BlockStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString("{\n")
	for _, stmt := range b.Statements {
		buf.WriteString(stmt.String())
	}
	if b.NestLevel == 0 {
		buf.WriteString("}")
	} else {
		buf.WriteString(indent(b.NestLevel-1) + "}")
	}

	return buf.String()
}
