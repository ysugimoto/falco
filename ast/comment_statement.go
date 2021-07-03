package ast

import (
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
