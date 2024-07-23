package context

import (
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/resolver"
	"github.com/ysugimoto/falco/snippets"
)

type Option func(c *Context)

func WithResolver(rslv resolver.Resolver) Option {
	return func(c *Context) {
		c.Resolver = rslv
	}
}

func WithSnippets(fs *snippets.Snippets) Option {
	return func(c *Context) {
		c.FastlySnippets = fs
	}
}

func WithMaxBackends(maxBackends int) Option {
	return func(c *Context) {
		c.OverrideMaxBackends = maxBackends
	}
}

func WithMaxAcls(maxAcls int) Option {
	return func(c *Context) {
		c.OverrideMaxAcls = maxAcls
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

func WithInjectEdgeDictionaries(ed map[string]config.EdgeDictionary) Option {
	return func(c *Context) {
		c.InjectEdgeDictionaries = ed
	}
}

func WithActualResponse(is bool) Option {
	return func(c *Context) {
		c.IsActualResponse = is
	}
}
