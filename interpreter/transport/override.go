package transport

import (
	"github.com/gobwas/glob"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
)

func getOverrideBackend(ctx *context.Context, backendName string) (*config.OverrideBackend, error) {
	for key, val := range ctx.OverrideBackends {
		p, err := glob.Compile(key)
		if err != nil {
			return nil, exception.System("Invalid glob pattern is provided: %s, %s", key, err)
		}
		if !p.Match(backendName) {
			continue
		}
		return val, nil
	}
	return nil, nil
}
