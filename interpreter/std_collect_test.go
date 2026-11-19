package interpreter

import (
	"testing"

	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

// On Fastly, reading a header that `add` has repeated yields only the first
// line until std.collect merges them.
// Verified at https://fiddle.fastly.dev/fiddle/ae47c1d2
func TestStdCollectAfterAdd(t *testing.T) {
	t.Run("request header", func(t *testing.T) {
		vcl := `sub vcl_recv {
			set req.http.X-Q = "q1";
			add req.http.X-Q = "q2";
			set req.http.Before = req.http.X-Q;
			std.collect(req.http.X-Q);
			set req.http.After = req.http.X-Q;
		}`
		assertInterpreter(t, vcl, context.RecvScope, map[string]value.Value{
			"req.http.Before": &value.String{Value: "q1"},
			"req.http.After":  &value.String{Value: "q1, q2"},
		}, false)
	})

	t.Run("request header with custom separator", func(t *testing.T) {
		vcl := `sub vcl_recv {
			set req.http.X-Q = "s1";
			add req.http.X-Q = "s2";
			std.collect(req.http.X-Q, "|");
			set req.http.After = req.http.X-Q;
		}`
		assertInterpreter(t, vcl, context.RecvScope, map[string]value.Value{
			"req.http.After": &value.String{Value: "s1| s2"},
		}, false)
	})

	t.Run("header name casing may differ between statements", func(t *testing.T) {
		vcl := `sub vcl_recv {
			set req.http.x-q = "c1";
			add req.http.X-Q = "c2";
			std.collect(req.http.x-Q);
			set req.http.After = req.http.X-q;
		}`
		assertInterpreter(t, vcl, context.RecvScope, map[string]value.Value{
			"req.http.After": &value.String{Value: "c1, c2"},
		}, false)
	})

	t.Run("response header", func(t *testing.T) {
		vcl := `sub vcl_deliver {
			set resp.http.Server-Timing = "s1;dur=1";
			add resp.http.Server-Timing = "s2;dur=2";
			set resp.http.Before = resp.http.Server-Timing;
			std.collect(resp.http.Server-Timing);
			set resp.http.After = resp.http.Server-Timing;
		}`
		assertInterpreter(t, vcl, context.DeliverScope, map[string]value.Value{
			"resp.http.Before": &value.String{Value: "s1;dur=1"},
			"resp.http.After":  &value.String{Value: "s1;dur=1, s2;dur=2"},
		}, false)
	})
}
