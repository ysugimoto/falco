package ast

import (
	"bytes"
)

type LogStatement struct {
	*Meta
	Value Expression
}

func (l *LogStatement) Statement()     {}
func (l *LogStatement) GetMeta() *Meta { return l.Meta }
func (l *LogStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(l.LeadingComment(lineFeed))
	buf.WriteString(indent(l.Nest) + "log" + paddingLeft(l.Value.String()) + ";")
	buf.WriteString(l.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
