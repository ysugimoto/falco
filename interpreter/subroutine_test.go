package interpreter

import (
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestFunctionSubroutine(t *testing.T) {
	tests := []struct {
		name       string
		vcl        string
		assertions map[string]value.Value
	}{
		{
			name: "Functional subroutine returns a value",
			vcl: `sub compute INTEGER {
				return 2;
			}

			sub vcl_recv {
				declare local var.myint INTEGER;
				set var.myint = compute();
				set req.http.X-Int-Value = var.myint;
			}
			`,
			assertions: map[string]value.Value{
				"req.http.X-Int-Value": &value.LenientString{
					Values: []value.Value{
						&value.Integer{Value: 2},
					},
				},
			},
		},
		{
			// ref: https://github.com/ysugimoto/falco/issues/241
			name: "Functional subroutine returns a value from if",
			vcl: `sub compute INTEGER {
				if (true) {
					return 2;
				}
				return 3;
			}

			sub vcl_recv {
				declare local var.myint INTEGER;
				set var.myint = compute();
				set req.http.X-Int-Value = var.myint;
			}
			`,
			assertions: map[string]value.Value{
				"req.http.X-Int-Value": &value.LenientString{
					Values: []value.Value{
						&value.Integer{Value: 2},
					},
				},
			},
		},
		{
			name: "Functional subroutine returns a value from switch",
			vcl: `sub compute INTEGER {
				switch (true) {
				default:
					return 2;
					break;
				}
				return 3;
			}

			sub vcl_recv {
				declare local var.myint INTEGER;
				set var.myint = compute();
				set req.http.X-Int-Value = var.myint;
			}
			`,
			assertions: map[string]value.Value{
				"req.http.X-Int-Value": &value.LenientString{
					Values: []value.Value{
						&value.Integer{Value: 2},
					},
				},
			},
		},
		{
			name: "Functional subroutine returns a value from bare block",
			vcl: `sub compute INTEGER {
				{
					return 2;
				}
			}

			sub vcl_recv {
				declare local var.myint INTEGER;
				set var.myint = compute();
				set req.http.X-Int-Value = var.myint;
			}
			`,
			assertions: map[string]value.Value{
				"req.http.X-Int-Value": &value.LenientString{
					Values: []value.Value{
						&value.Integer{Value: 2},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInterpreter(t, tt.vcl, context.RecvScope, tt.assertions, false)
		})
	}
}
