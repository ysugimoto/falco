package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type SyntheticStatement struct {
	Token     token.Token
	Value     Expression
	NestLevel int
	Comments  Comments
}

func (s *SyntheticStatement) statement()            {}
func (s *SyntheticStatement) GetComments() string   { return s.Comments.String() }
func (s *SyntheticStatement) GetToken() token.Token { return s.Token }
func (s *SyntheticStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.Comments.String())
	buf.WriteString(indent(s.NestLevel) + "synthetic " + s.Value.String() + ";\n")

	return buf.String()
}
