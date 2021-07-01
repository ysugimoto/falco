package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type SubroutineDeclaration struct {
	Token    token.Token
	Name     *Ident
	Block    *BlockStatement
	Comments Comments
}

func (s *SubroutineDeclaration) statement()            {}
func (s *SubroutineDeclaration) GetComments() string   { return s.Comments.String() }
func (s *SubroutineDeclaration) GetToken() token.Token { return s.Token }
func (s *SubroutineDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.Comments.String())
	buf.WriteString("sub ")
	buf.WriteString(s.Name.String())
	buf.WriteString(" " + s.Block.String())
	buf.WriteString("\n")

	return buf.String()
}
