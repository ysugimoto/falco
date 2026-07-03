package interpreter

import (
	"testing"

	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

// On Fastly an appending assignment prepends the current header value to the
// assembled string, so `set req.http.X += "y"` appends rather than overwrites.
func TestAppendAssignHeader(t *testing.T) {
	t.Run("+= appends to an existing request header", func(t *testing.T) {
		vcl := `sub vcl_recv {
			set req.http.A = "abc";
			set req.http.A += "xy";
		}`
		assertInterpreter(t, vcl, context.RecvScope, map[string]value.Value{
			"req.http.A": &value.String{Value: "abcxy"},
		}, false)
	})

	t.Run("+= onto an unset request header sets it", func(t *testing.T) {
		vcl := `sub vcl_recv {
			set req.http.A += "xy";
		}`
		assertInterpreter(t, vcl, context.RecvScope, map[string]value.Value{
			"req.http.A": &value.String{Value: "xy"},
		}, false)
	})

	t.Run("+= concatenates several fragments", func(t *testing.T) {
		vcl := `sub vcl_recv {
			set req.http.A = "1";
			set req.http.A += "2";
			set req.http.A += "3" "4";
		}`
		assertInterpreter(t, vcl, context.RecvScope, map[string]value.Value{
			"req.http.A": &value.String{Value: "1234"},
		}, false)
	})

	t.Run("plain = still overwrites", func(t *testing.T) {
		vcl := `sub vcl_recv {
			set req.http.A = "abc";
			set req.http.A = "xy";
		}`
		assertInterpreter(t, vcl, context.RecvScope, map[string]value.Value{
			"req.http.A": &value.String{Value: "xy"},
		}, false)
	})

	t.Run("+= appends to a response header", func(t *testing.T) {
		vcl := `sub vcl_deliver {
			set resp.http.A = "abc";
			set resp.http.A += "xy";
		}`
		assertInterpreter(t, vcl, context.DeliverScope, map[string]value.Value{
			"resp.http.A": &value.String{Value: "abcxy"},
		}, false)
	})
}
