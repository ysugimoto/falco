package ast

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/token"
)

type CommentStatement struct {
	Token     token.Token
	Value     string
	NestLevel int
}

func (c *CommentStatement) statement()            {}
func (c *CommentStatement) GetComments() string   { return c.String() }
func (c *CommentStatement) GetToken() token.Token { return c.Token }
func (c *CommentStatement) String() string {
	return indent(c.NestLevel) + c.Value + "\n"
}

type Comments []*CommentStatement

func (c Comments) String() string {
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
