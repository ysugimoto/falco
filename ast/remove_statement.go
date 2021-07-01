package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type RemoveStatement struct {
	Token     token.Token
	Ident     *Ident
	NestLevel int
	Comments  Comments
}

func (r *RemoveStatement) statement()            {}
func (r *RemoveStatement) GetComments() string   { return r.Comments.String() }
func (r *RemoveStatement) GetToken() token.Token { return r.Token }
func (r *RemoveStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.Comments.String())
	buf.WriteString(indent(r.NestLevel) + "remove ")
	buf.WriteString(r.Ident.String() + ";\n")

	return buf.String()
}
