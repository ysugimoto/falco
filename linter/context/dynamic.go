package context

import (
	"github.com/ysugimoto/falco/linter/types"
)

func dynamicBackend() *Object {
	return &Object{
		Items: map[string]*Object{
			"connections_open": {
				Items: map[string]*Object{},
				Value: &Accessor{
					Get:       types.IntegerType,
					Unset:     false,
					Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
					Reference: "https://developer.fastly.com/reference/vcl/variables/backend-connection/backend-connections-open/",
				},
			},
			"connections_used": {
				Items: map[string]*Object{},
				Value: &Accessor{
					Get:       types.IntegerType,
					Unset:     false,
					Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
					Reference: "https://developer.fastly.com/reference/vcl/variables/backend-connection/backend-connections-used/",
				},
			},
			"healthy": {
				Items: map[string]*Object{},
				Value: &Accessor{
					Get:       types.BoolType,
					Unset:     false,
					Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
					Reference: "https://developer.fastly.com/reference/vcl/variables/backend-connection/backend-healthy/",
				},
			},
		},
	}
}

func dynamicDirector() *Object {
	return &Object{
		Items: map[string]*Object{
			"healthy": {
				Items: map[string]*Object{},
				Value: &Accessor{
					Get:       types.BoolType,
					Unset:     false,
					Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
					Reference: "https://developer.fastly.com/reference/vcl/variables/miscellaneous/director-healthy/",
				},
			},
		},
	}
}
