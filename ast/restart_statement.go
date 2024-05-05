package ast

import (
	"bytes"
)

type RestartStatement struct {
	*Meta
}

func (r *RestartStatement) Statement()     {}
func (r *RestartStatement) GetMeta() *Meta { return r.Meta }
func (r *RestartStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(r.LeadingComment(lineFeed))
	buf.WriteString(indent(r.Nest) + "restart")
	buf.WriteString(paddingLeft(r.InfixComment(inline)))
	buf.WriteString(";")
	buf.WriteString(r.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
