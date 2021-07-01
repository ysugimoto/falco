package parser

import (
	"github.com/ysugimoto/falco/ast"
)

type OptionFunc func(o *Option)

type Option struct {
	NestLevel int
	Comments  ast.Comments
}

func withComments(comments ast.Comments) OptionFunc {
	return func(o *Option) {
		o.Comments = comments
	}
}

func withNestLevel(lv int) OptionFunc {
	return func(o *Option) {
		o.NestLevel = lv
	}
}

func collect(opts []OptionFunc) *Option {
	o := &Option{
		Comments: ast.Comments{},
	}

	for i := range opts {
		opts[i](o)
	}
	return o
}
