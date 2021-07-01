package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type RestartStatement struct {
	Token     token.Token
	NestLevel int
	Comments  Comments
}

func (r *RestartStatement) statement()            {}
func (r *RestartStatement) GetComments() string   { return r.Comments.String() }
func (r *RestartStatement) GetToken() token.Token { return r.Token }
func (r *RestartStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.Comments.String())
	buf.WriteString(indent(r.NestLevel) + "restart;\n")

	return buf.String()
}
