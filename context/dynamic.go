package context

import (
	"github.com/ysugimoto/falco/types"
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

func dynamicRateCounter() *Object {
	return &Object{
		Items: map[string]*Object{
			"bucket": {
				Items: map[string]*Object{
					"10s": {
						Items: map[string]*Object{},
						Value: &Accessor{
							Get:       types.IntegerType,
							Unset:     false,
							Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
							Reference: "https://developer.fastly.com/reference/vcl/variables/backend-connection/ratecounter-bucket-10s/",
						},
					},
					"20s": {
						Items: map[string]*Object{},
						Value: &Accessor{
							Get:       types.IntegerType,
							Unset:     false,
							Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
							Reference: "https://developer.fastly.com/reference/vcl/variables/backend-connection/ratecounter-bucket-20s/",
						},
					},
					"30s": {
						Items: map[string]*Object{},
						Value: &Accessor{
							Get:       types.IntegerType,
							Unset:     false,
							Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
							Reference: "https://developer.fastly.com/reference/vcl/variables/backend-connection/ratecounter-bucket-30s/",
						},
					},
					"40s": {
						Items: map[string]*Object{},
						Value: &Accessor{
							Get:       types.IntegerType,
							Unset:     false,
							Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
							Reference: "https://developer.fastly.com/reference/vcl/variables/backend-connection/ratecounter-bucket-40s/",
						},
					},
					"50s": {
						Items: map[string]*Object{},
						Value: &Accessor{
							Get:       types.IntegerType,
							Unset:     false,
							Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
							Reference: "https://developer.fastly.com/reference/vcl/variables/backend-connection/ratecounter-bucket-50s/",
						},
					},
					"60s": {
						Items: map[string]*Object{},
						Value: &Accessor{
							Get:       types.IntegerType,
							Unset:     false,
							Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
							Reference: "https://developer.fastly.com/reference/vcl/variables/backend-connection/ratecounter-bucket-60s/",
						},
					},
				},
			},
			"rate": {
				Items: map[string]*Object{
					"1s": {
						Items: map[string]*Object{},
						Value: &Accessor{
							Get:       types.FloatType,
							Unset:     false,
							Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
							Reference: "https://developer.fastly.com/reference/vcl/variables/backend-connection/ratecounter-rate-1s/",
						},
					},
					"10s": {
						Items: map[string]*Object{},
						Value: &Accessor{
							Get:       types.FloatType,
							Unset:     false,
							Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
							Reference: "https://developer.fastly.com/reference/vcl/variables/backend-connection/ratecounter-rate-10s/",
						},
					},
					"60s": {
						Items: map[string]*Object{},
						Value: &Accessor{
							Get:       types.FloatType,
							Unset:     false,
							Scopes:    RECV | HASH | HIT | MISS | PASS | FETCH | ERROR | DELIVER | LOG,
							Reference: "https://developer.fastly.com/reference/vcl/variables/backend-connection/ratecounter-rate-60s/",
						},
					},
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
