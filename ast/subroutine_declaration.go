package ast

import (
	"bytes"
)

type SubroutineDeclaration struct {
	*Meta
	Name       *Ident
	Block      *BlockStatement
	ReturnType *Ident
}

func (s *SubroutineDeclaration) ID() uint64     { return s.Meta.ID }
func (s *SubroutineDeclaration) Statement()     {}
func (s *SubroutineDeclaration) GetMeta() *Meta { return s.Meta }
func (s *SubroutineDeclaration) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment(lineFeed))
	buf.WriteString("sub")
	buf.WriteString(padding(s.Name.String()))
	buf.WriteString(s.Block.String())
	buf.WriteString(s.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
