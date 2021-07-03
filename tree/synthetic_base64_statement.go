package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type SyntheticMeta64Statement struct {
	*Meta
	Value Expression
}

func (s *SyntheticMeta64Statement) statement()            {}
func (s *SyntheticMeta64Statement) GetToken() token.Token { return s.Token }
func (s *SyntheticMeta64Statement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.LeadingComment())
	buf.WriteString(indent(s.Nest) + "synthetic.base64 " + s.Value.String() + ";")
	buf.WriteString(s.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
