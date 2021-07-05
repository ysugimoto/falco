package ast

import (
	"bytes"
)

type RestartStatement struct {
	*Meta
}

func (r *RestartStatement) statement()     {}
func (r *RestartStatement) GetMeta() *Meta { return r.Meta }
func (r *RestartStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment())
	buf.WriteString(indent(r.Nest) + "restart;")
	buf.WriteString(r.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
