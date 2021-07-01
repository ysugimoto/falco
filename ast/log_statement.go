package ast

import (
	"bytes"

	"github.com/ysugimoto/falco/token"
)

type LogStatement struct {
	Token     token.Token
	Value     Expression
	NestLevel int
	Comments  Comments
}

func (l *LogStatement) statement()            {}
func (l *LogStatement) GetComments() string   { return l.Comments.String() }
func (l *LogStatement) GetToken() token.Token { return l.Token }
func (l *LogStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(l.Comments.String())
	buf.WriteString(indent(l.NestLevel) + "log " + l.Value.String() + ";\n")

	return buf.String()
}
