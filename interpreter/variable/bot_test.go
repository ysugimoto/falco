package variable

import (
	"slices"
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// fastly.bot.* variables are only accessible in RECV, HASH, DELIVER and LOG
// scopes (see https://www.fastly.com/documentation/reference/vcl/variables/
// miscellaneous/). Verified against the real Fastly VCL compiler.
func TestFastlyBotVariableScopes(t *testing.T) {
	boolVars := []string{
		FASTLY_BOT_ANALYZED,
		FASTLY_BOT_DETECTED,
		FASTLY_BOT_CATEGORY_IS_ACCESSIBILITY,
		FASTLY_BOT_CATEGORY_IS_AI_CRAWLER,
		FASTLY_BOT_CATEGORY_IS_AI_FETCHER,
		FASTLY_BOT_CATEGORY_IS_CONTENT_FETCHER,
		FASTLY_BOT_CATEGORY_IS_MONITORING_AND_SITE_TOOLS,
		FASTLY_BOT_CATEGORY_IS_ONLINE_MARKETING,
		FASTLY_BOT_CATEGORY_IS_PAGE_PREVIEW,
		FASTLY_BOT_CATEGORY_IS_PLATFORM_INTEGRATIONS,
		FASTLY_BOT_CATEGORY_IS_RESEARCH,
		FASTLY_BOT_CATEGORY_IS_SEARCH_ENGINE_CRAWLER,
		FASTLY_BOT_CATEGORY_IS_SEARCH_ENGINE_OPTIMIZATION,
		FASTLY_BOT_CATEGORY_IS_SECURITY_TOOLS,
		FASTLY_BOT_CATEGORY_IS_VERIFIED,
	}
	stringVars := []string{FASTLY_BOT_NAME, FASTLY_BOT_CATEGORY}
	allVars := append(append([]string{}, boolVars...), stringVars...)

	type scopeVar interface {
		Get(context.Scope, string) (value.Value, error)
	}
	type scopeCase struct {
		scope   context.Scope
		factory func(c *context.Context) scopeVar
	}

	allowed := map[string]scopeCase{
		"RECV":    {context.RecvScope, func(c *context.Context) scopeVar { return NewRecvScopeVariables(c) }},
		"HASH":    {context.HashScope, func(c *context.Context) scopeVar { return NewHashScopeVariables(c) }},
		"DELIVER": {context.DeliverScope, func(c *context.Context) scopeVar { return NewDeliverScopeVariables(c) }},
		"LOG":     {context.LogScope, func(c *context.Context) scopeVar { return NewLogScopeVariables(c) }},
	}
	denied := map[string]scopeCase{
		"PASS":  {context.PassScope, func(c *context.Context) scopeVar { return NewPassScopeVariables(c) }},
		"FETCH": {context.FetchScope, func(c *context.Context) scopeVar { return NewFetchScopeVariables(c) }},
		"HIT":   {context.HitScope, func(c *context.Context) scopeVar { return NewHitScopeVariables(c) }},
		"MISS":  {context.MissScope, func(c *context.Context) scopeVar { return NewMissScopeVariables(c) }},
		"ERROR": {context.ErrorScope, func(c *context.Context) scopeVar { return NewErrorScopeVariables(c) }},
	}

	isBool := func(name string) bool {
		return slices.Contains(boolVars, name)
	}

	for scope, tc := range allowed {
		for _, name := range allVars {
			ctx := createScopeVars("http://localhost/").ctx
			v, err := tc.factory(ctx).Get(tc.scope, name)
			if err != nil {
				t.Errorf("%s scope: expected %s to be accessible, got error: %v", scope, name, err)
				continue
			}
			if isBool(name) {
				if _, ok := v.(*value.Boolean); !ok {
					t.Errorf("%s scope: expected %s to be BOOL, got %T", scope, name, v)
				}
			} else {
				if _, ok := v.(*value.String); !ok {
					t.Errorf("%s scope: expected %s to be STRING, got %T", scope, name, v)
				}
			}
		}
	}

	for scope, tc := range denied {
		for _, name := range allVars {
			ctx := createScopeVars("http://localhost/").ctx
			if _, err := tc.factory(ctx).Get(tc.scope, name); err == nil {
				t.Errorf("%s scope: expected %s to be inaccessible, but no error returned", scope, name)
			}
		}
	}
}
