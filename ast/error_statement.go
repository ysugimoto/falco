package ast

import (
	"bytes"
)

type ErrorStatement struct {
	*Meta
	Code     Expression
	Argument Expression
}

func (e *ErrorStatement) ID() uint64     { return e.Meta.ID }
func (e *ErrorStatement) Statement()     {}
func (e *ErrorStatement) GetMeta() *Meta { return e.Meta }
func (e *ErrorStatement) String() string {
	var buf bytes.Buffer

	buf.WriteString(e.LeadingComment(lineFeed))
	buf.WriteString(indent(e.Nest) + "error " + e.Code.String())
	if e.Argument != nil {
		buf.WriteString(" " + e.Argument.String())
	}
	buf.WriteString(";")
	buf.WriteString(e.TrailingComment(inline))
	buf.WriteString("\n")

	return buf.String()
}
