package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type RestartStatement struct {
	*Meta
}

func (r *RestartStatement) statement()            {}
func (r *RestartStatement) GetToken() token.Token { return r.Token }
func (r *RestartStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment())
	buf.WriteString(indent(r.Nest) + "restart;")
	buf.WriteString(r.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
