package interpreter

import (
	"testing"

	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

// Fastly compiles add on req.http/resp.http in vcl_log but ignores it,
// while set still works and std.collect still joins earlier lines.
// Verified at https://fiddle.fastly.dev/fiddle/6da33a75 and
// https://fiddle.fastly.dev/fiddle/84065918
func TestAddStatementInLog(t *testing.T) {
	// No absent-header case for resp.http: falco reads any absent resp.http
	// header in vcl_log as an empty string rather than not set (Fastly reads
	// it as null), which is a separate bug.
	t.Run("request header is not added", func(t *testing.T) {
		vcl := `sub vcl_log {
			add req.http.X-Log = "r1";
		}`
		assertInterpreter(t, vcl, context.LogScope, map[string]value.Value{
			"req.http.X-Log": &value.String{IsNotSet: true},
		}, false)
	})

	t.Run("no line is appended to an existing header", func(t *testing.T) {
		vcl := `sub vcl_log {
			set req.http.X-Pre = "p1";
			set resp.http.X-Pre = "q1";
			add req.http.X-Pre = "p2";
			add resp.http.X-Pre = "q2";
			std.collect(req.http.X-Pre, "|");
			std.collect(resp.http.X-Pre, "|");
		}`
		assertInterpreter(t, vcl, context.LogScope, map[string]value.Value{
			"req.http.X-Pre":  &value.String{Value: "p1"},
			"resp.http.X-Pre": &value.String{Value: "q1"},
		}, false)
	})

	// https://fiddle.fastly.dev/fiddle/cca4d87d
	t.Run("ignored add is not charged to the request workspace", func(t *testing.T) {
		vcl := `sub vcl_log {
			declare local var.w0 INTEGER;
			declare local var.w1 INTEGER;
			set var.w0 = workspace.bytes_free;
			add req.http.X-Big = "0123456789012345678901234567890123456789";
			set var.w1 = workspace.bytes_free;
			if (var.w0 == var.w1) {
				set req.http.X-Same = "yes";
			} else {
				set req.http.X-Same = "no";
			}
		}`
		assertInterpreter(t, vcl, context.LogScope, map[string]value.Value{
			"req.http.X-Same": &value.String{Value: "yes"},
		}, false)
	})

	// Fastly rejects these at compile time
	// (https://fiddle.fastly.dev/fiddle/6fe54095); falco raises a runtime
	// error, as in the other scopes.
	t.Run("protected header is rejected", func(t *testing.T) {
		vcl := `sub vcl_log {
			add resp.http.Fastly-FF = "x";
		}`
		assertInterpreter(t, vcl, context.LogScope, map[string]value.Value{}, true)
	})

	t.Run("non-header target falls through to base and errors", func(t *testing.T) {
		vcl := `sub vcl_log {
			add bereq.http.X = "x";
		}`
		assertInterpreter(t, vcl, context.LogScope, map[string]value.Value{}, true)
	})
}
