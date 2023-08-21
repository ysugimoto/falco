package context

import (
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

func WithDebug() Option {
	return func(c *Context) {
		c.Debug = true
	}
}

func WithMaxBackends(max int) Option {
	return func(c *Context) {
		c.OverrideMaxBackends = max
	}
}

func WithMaxAcls(max int) Option {
	return func(c *Context) {
		c.OverrideMaxAcls = max
	}
}
