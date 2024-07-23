package ast

import (
	"bytes"
)

type SetStatement struct {
	*Meta
	Ident    *Ident
	Operator *Operator
	Value    Expression
}

func (s *SetStatement) ID() uint64     { return s.Meta.ID }
func (s *SetStatement) Statement()     {}
func (s *SetStatement) GetMeta() *Meta { return s.Meta }
func (s *SetStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment(lineFeed))
	buf.WriteString(indent(s.Nest) + "set")
	buf.WriteString(paddingLeft(s.Ident.String()))
	buf.WriteString(" " + s.Operator.String())
	buf.WriteString(paddingLeft(s.Value.String()) + ";")
	buf.WriteString(s.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
