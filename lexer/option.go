package lexer

import (
	"maps"

	"github.com/ysugimoto/falco/token"
)

type OptionFunc func(o *Option)

type Option struct {
	Filename string
	Customs  map[string]token.TokenType
	// more field if exists
}

func WithFile(filename string) OptionFunc {
	return func(o *Option) {
		o.Filename = filename
	}
}

func WithCustomTokens(tokenMap map[string]token.TokenType) OptionFunc {
	return func(o *Option) {
		maps.Copy(o.Customs, tokenMap)
	}
}

func collect(opts []OptionFunc) *Option {
	o := &Option{
		Filename: "",
		Customs:  make(map[string]token.TokenType),
	}

	for i := range opts {
		opts[i](o)
	}
	return o
}
