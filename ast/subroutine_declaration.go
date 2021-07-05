package ast

import (
	"bytes"
)

type SubroutineDeclaration struct {
	*Meta
	Name  *Ident
	Block *BlockStatement
}

func (s *SubroutineDeclaration) statement()     {}
func (s *SubroutineDeclaration) GetMeta() *Meta { return s.Meta }
func (s *SubroutineDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment())
	buf.WriteString("sub ")
	buf.WriteString(s.Name.String())
	buf.WriteString(" " + s.Block.String())
	buf.WriteString(s.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
