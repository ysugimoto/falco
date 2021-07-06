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

func (c *Comment) String() string {
	return c.Value
}

type Comments []*Comment

func (c Comments) String() string {
	if len(c) == 0 {
		return ""
	}
	var buf bytes.Buffer

	for i := range c {
		buf.WriteString(c[i].String())
	}

	return buf.String()
}

func (c *Comments) Annotations() []string {
	var annotations []string

	lines := strings.Split(c.String(), "\n")
	for i := range lines {
		l := strings.TrimLeft(lines[i], " */#")
		if strings.HasPrefix(l, "@") {
			annotations = append(annotations, strings.TrimPrefix(l, "@"))
		}
	}

	return annotations
}
