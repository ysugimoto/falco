package context

import (
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/interpreter/value"
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

func WithOverrideVariales(variables map[string]any) Option {
	return func(c *Context) {
		for k, v := range variables {
			switch t := v.(type) {
			case int:
				c.OverrideVariables[k] = &value.Integer{Value: int64(t)}
			case string:
				c.OverrideVariables[k] = &value.String{Value: t}
			case float64:
				c.OverrideVariables[k] = &value.Float{Value: float64(t)}
			case bool:
				c.OverrideVariables[k] = &value.Boolean{Value: t}
			}
		}
	}
}

func WithCoverage(cv *shared.Coverage) Option {
	return func(c *Context) {
		c.Coverage = cv
	}
}
