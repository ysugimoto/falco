package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type SubroutineDeclaration struct {
	*Meta
	Name  *Ident
	Block *BlockStatement
}

func (s *SubroutineDeclaration) statement()            {}
func (s *SubroutineDeclaration) GetToken() token.Token { return s.Token }
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
