package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type SetStatement struct {
	Token     token.Token
	Ident     *Ident
	Operator  *Operator
	Value     Expression
	NestLevel int
	Comments  Comments
}

func (s *SetStatement) statement()            {}
func (s *SetStatement) GetComments() string   { return s.Comments.String() }
func (s *SetStatement) GetToken() token.Token { return s.Token }
func (s *SetStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(s.Comments.String())
	buf.WriteString(indent(s.NestLevel) + "set ")
	buf.WriteString(s.Ident.String())
	buf.WriteString(" " + s.Operator.String() + " ")
	buf.WriteString(s.Value.String() + ";\n")

	return buf.String()
}
