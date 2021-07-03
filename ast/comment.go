package ast

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/token"
)

type Comment struct {
	Token token.Token
	Value string
}

func (c *Comment) String(nest int) string {
	if strings.HasPrefix(c.Value, "\n") {
		return indent(nest) + c.Value
	}
	return indent(nest) + c.Value + " "
}

type Comments []*Comment

func (c Comments) String(nest int) string {
	if len(c) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range c {
		buf.WriteString(c[i].String(nest))
	}

	return buf.String()
}

func (c *Comments) Annotations() []string {
	var annotations []string

	lines := strings.Split(c.String(0), "\n")
	for i := range lines {
		l := strings.TrimLeft(lines[i], " */#")
		if strings.HasPrefix(l, "@") {
			annotations = append(annotations, strings.TrimPrefix(l, "@"))
		}
	}

	return annotations
}
