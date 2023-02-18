package context

import (
	"github.com/ysugimoto/falco/resolver"
)

type Option func(c *Context)

func WithResolver(rslv resolver.Resolver) Option {
	return func(c *Context) {
		c.resolver = rslv
	}
}

func WithFastlySnippets(fs *FastlySnippet) Option {
	return func(c *Context) {
		c.fastlySnippets = fs
	}
}
