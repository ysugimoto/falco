package context

import (
	"maps"
	"time"

	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/resolver"
	"github.com/ysugimoto/falco/snippet"
	"github.com/ysugimoto/falco/tester/shared"
)

type Option func(c *Context)

func WithResolver(rslv resolver.Resolver) Option {
	return func(c *Context) {
		c.Resolver = rslv
	}
}

func WithSnippets(fs *snippet.Snippets) Option {
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

func WithOverrideVariables(variables map[string]any) Option {
	return func(c *Context) {
		maps.Copy(c.OverrideVariables, variables)
	}
}

func WithCoverage(cv *shared.Coverage) Option {
	return func(c *Context) {
		c.Coverage = cv
	}
}

func WithTLServer(tls bool) Option {
	return func(c *Context) {
		c.TLSServer = tls
	}
}

func WithFixedTime(t time.Time) Option {
	return func(c *Context) {
		c.FixedTime = &t
	}
}
