package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type SyntheticStatement struct {
	*Meta
	Value Expression
}

func (s *SyntheticStatement) statement()            {}
func (s *SyntheticStatement) GetToken() token.Token { return s.Token }
func (s *SyntheticStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment())
	buf.WriteString(indent(s.Nest) + "synthetic " + s.Value.String() + ";")
	buf.WriteString(s.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
