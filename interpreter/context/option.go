package context

import (
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/context"
	"github.com/ysugimoto/falco/resolver"
)

type Option func(c *Context)

func WithResolver(rslv resolver.Resolver) Option {
	return func(c *Context) {
		c.Resolver = rslv
	}
}

func WithFastlySnippets(fs *context.FastlySnippet) Option {
	return func(c *Context) {
		c.FastlySnippets = fs
	}
}

func WithConfig(cfg config.Simulator) Option {
	return func(c *Context) {
		c.Config = cfg
	}
}
