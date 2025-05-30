package context

import (
	"github.com/ysugimoto/falco/resolver"
	"github.com/ysugimoto/falco/snippet"
)

type Option func(c *Context)

func WithResolver(rslv resolver.Resolver) Option {
	return func(c *Context) {
		c.resolver = rslv
	}
}

func WithSnippets(fs *snippet.Snippets) Option {
	return func(c *Context) {
		c.fastlySnippets = fs
	}
}
