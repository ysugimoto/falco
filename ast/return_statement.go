package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type ReturnStatement struct {
	Token     token.Token
	Ident     *Ident
	NestLevel int
	Comments  Comments
}

func (r *ReturnStatement) statement()            {}
func (r *ReturnStatement) GetComments() string   { return r.Comments.String() }
func (r *ReturnStatement) GetToken() token.Token { return r.Token }
func (r *ReturnStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.Comments.String())
	buf.WriteString(indent(r.NestLevel) + "return(" + r.Ident.String() + ");\n")

	return buf.String()
}
