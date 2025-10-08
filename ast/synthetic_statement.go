package ast

import (
	"bytes"
)

type SyntheticStatement struct {
	*Meta
	Value Expression
}

func (s *SyntheticStatement) ID() uint64     { return s.Meta.ID }
func (s *SyntheticStatement) Statement()     {}
func (s *SyntheticStatement) GetMeta() *Meta { return s.Meta }
func (s *SyntheticStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment(lineFeed))
	buf.WriteString(indent(s.Nest) + "synthetic")
	buf.WriteString(paddingLeft(s.Value.String()))
	buf.WriteString(";")
	buf.WriteString(s.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
