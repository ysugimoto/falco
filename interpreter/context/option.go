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

func WithRequest(r *config.RequestConfig) Option {
	return func(c *Context) {
		c.OverrideRequest = r
	}
}

func WithOverrideBackends(ov map[string]*config.OverrideBackend) Option {
	return func(c *Context) {
		c.OverrideBackends = ov
	}
}

func WithOverrideHost(host string) Option {
	return func(c *Context) {
		c.OriginalHost = host
	}
}
