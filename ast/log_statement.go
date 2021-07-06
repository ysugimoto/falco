package ast

import (
	"bytes"
)

type LogStatement struct {
	*Meta
	Value Expression
}

func (l *LogStatement) statement()     {}
func (l *LogStatement) GetMeta() *Meta { return l.Meta }
func (l *LogStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(l.LeadingComment())
	buf.WriteString(indent(l.Nest) + "log " + l.Value.String() + ";")
	buf.WriteString(l.TrailingComment())
	buf.WriteString("\n")

	return buf.String()
}
