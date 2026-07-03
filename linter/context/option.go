package context

import (
	"github.com/ysugimoto/falco/v2/resolver"
	"github.com/ysugimoto/falco/v2/snippet"
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
