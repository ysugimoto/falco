package ast

import (
	"bytes"
)

type BlockStatement struct {
	*Meta
	Statements []Statement
}

func (b *BlockStatement) statement()     {}
func (b *BlockStatement) GetMeta() *Meta { return b.Meta }
func (b *BlockStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString("{\n")
	for _, stmt := range b.Statements {
		buf.WriteString(stmt.String())
	}
	buf.WriteString(b.InfixComment())
	if b.Nest == 0 {
		buf.WriteString("}")
	} else {
		buf.WriteString(indent(b.Nest-1) + "}")
	}

	return buf.String()
}
