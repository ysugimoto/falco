package variable

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestOverrideVariables(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]any
		expect    any
	}{
		{
			name: "client.bot.name",
			overrides: map[string]any{
				"client.bot.name": "overridden",
			},
			expect: "overridden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.New(context.WithOverrideVariables(tt.overrides))
			vars := NewAllScopeVariables(ctx)
			v, err := vars.Get(context.RecvScope, tt.name)
			if err != nil {
				t.Errorf("Unexpected error: %s", err)
				return
			}
			var expect value.Value
			switch t := tt.expect.(type) {
			case int:
				expect = &value.Integer{Value: int64(t)}
			case string:
				expect = &value.String{Value: t}
			case float64:
				expect = &value.Float{Value: float64(t)}
			case bool:
				expect = &value.Boolean{Value: t}
			default:
				expect = value.Null
			}
			if diff := cmp.Diff(expect, v); diff != "" {
				t.Errorf("Overridden variable mismatch, diff=%s", diff)
			}
		})
	}
}

func TestOverrideIPVariablesWithString(t *testing.T) {
	tests := []struct {
		name      string
		varName   string
		override  string
		expectIP  net.IP
		expectStr bool // true if the value should remain as String (invalid IP)
	}{
		{
			name:     "client.ip with IPv4 string",
			varName:  "client.ip",
			override: "192.0.2.1",
			expectIP: net.ParseIP("192.0.2.1"),
		},
		{
			name:     "client.ip with another IPv4 string",
			varName:  "client.ip",
			override: "198.51.100.1",
			expectIP: net.ParseIP("198.51.100.1"),
		},
		{
			name:     "beresp.backend.src_ip with IPv4 string",
			varName:  "beresp.backend.src_ip",
			override: "203.0.113.1",
			expectIP: net.ParseIP("203.0.113.1"),
		},
		{
			name:     "client.ip with IPv6 string",
			varName:  "client.ip",
			override: "2001:db8::1",
			expectIP: net.ParseIP("2001:db8::1"),
		},
		{
			name:     "beresp.backend.src_ip with IPv6 string",
			varName:  "beresp.backend.src_ip",
			override: "2001:db8:1::ab9:C0A8:102",
			expectIP: net.ParseIP("2001:db8:1::ab9:C0A8:102"),
		},
		{
			name:      "client.ip with invalid IP string",
			varName:   "client.ip",
			override:  "not-an-ip",
			expectStr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.New(context.WithOverrideVariables(map[string]any{
				tt.varName: tt.override,
			}))
			vars := NewAllScopeVariables(ctx)
			v, err := vars.Get(context.RecvScope, tt.varName)
			if err != nil {
				t.Errorf("Unexpected error: %s", err)
				return
			}
			if tt.expectStr {
				if v.Type() != value.StringType {
					t.Errorf("Expected StringType, got %s", v.Type())
				}
				return
			}
			if v.Type() != value.IpType {
				t.Errorf("Expected IpType, got %s", v.Type())
				return
			}
			ip := value.Unwrap[*value.IP](v)
			if !ip.Value.Equal(tt.expectIP) {
				t.Errorf("IP mismatch, expect=%s, got=%s", tt.expectIP, ip.Value)
			}
		})
	}
}

func TestOverrideIPVariablesWithIPValue(t *testing.T) {
	tests := []struct {
		name    string
		varName string
		ip      net.IP
	}{
		{
			name:    "client.ip with IPv4 IP value",
			varName: "client.ip",
			ip:      net.ParseIP("192.0.2.100"),
		},
		{
			name:    "client.ip with IPv6 IP value",
			varName: "client.ip",
			ip:      net.ParseIP("2001:db8::100"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.New()
			ctx.OverrideVariables[tt.varName] = &value.IP{Value: tt.ip}
			vars := NewAllScopeVariables(ctx)
			v, err := vars.Get(context.RecvScope, tt.varName)
			if err != nil {
				t.Errorf("Unexpected error: %s", err)
				return
			}
			if v.Type() != value.IpType {
				t.Errorf("Expected IpType, got %s", v.Type())
				return
			}
			ip := value.Unwrap[*value.IP](v)
			if !ip.Value.Equal(tt.ip) {
				t.Errorf("IP mismatch, expect=%s, got=%s", tt.ip, ip.Value)
			}
		})
	}
}
