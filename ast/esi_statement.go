package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type EsiStatement struct {
	Token     token.Token
	NestLevel int
	Comments  Comments
}

func (e *EsiStatement) statement()            {}
func (e *EsiStatement) GetComments() string   { return e.Comments.String() }
func (e *EsiStatement) GetToken() token.Token { return e.Token }
func (e *EsiStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(e.Comments.String())
	buf.WriteString(indent(e.NestLevel) + "esi;\n")

	return buf.String()
}
