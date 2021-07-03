package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type BlockStatement struct {
	*Base
	Token      token.Token
	Statements []Statement
}

func (b *BlockStatement) statement()            {}
func (b *BlockStatement) GetToken() token.Token { return b.Token }
func (b *BlockStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(b.LeadingComment())
	buf.WriteString("{\n")
	for _, stmt := range b.Statements {
		buf.WriteString(stmt.String())
	}
	if b.Nest == 0 {
		buf.WriteString("}")
	} else {
		buf.WriteString(indent(b.Nest-1) + "}")
	}
	buf.WriteString(b.TrailingComment())

	return buf.String()
}
