package ast

import (
	"bytes"
	"strings"
)

type SubroutineParameter struct {
	*Meta
	Type *Ident
	Name *Ident
}

func (s *SubroutineParameter) GetMeta() *Meta { return s.Meta }

type SubroutineDeclaration struct {
	*Meta
	Name       *Ident
	Parameters []*SubroutineParameter
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

	if len(s.Parameters) > 0 {
		buf.WriteString("(")
		params := make([]string, len(s.Parameters))
		for i, p := range s.Parameters {
			params[i] = p.Type.String() + " " + p.Name.String()
		}
		buf.WriteString(strings.Join(params, ", "))
		buf.WriteString(")")
	}

	if s.ReturnType != nil {
		buf.WriteString(" " + s.ReturnType.String())
	}

	buf.WriteString(s.Block.String())
	buf.WriteString(s.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
