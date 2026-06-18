package interpreter

import (
	"strconv"
	"strings"
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/limitations"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestRequestWorkspaceLimit(t *testing.T) {
	t.Run("ordinary header writes stay within the workspace", func(t *testing.T) {
		vcl := `sub vcl_recv {
			set req.http.A = "hello";
			set req.http.B = "world";
		}`
		assertInterpreter(t, vcl, context.RecvScope, map[string]value.Value{
			"req.http.A": &value.String{Value: "hello"},
		}, false)
	})

	t.Run("rewriting a header until the workspace overflows fails", func(t *testing.T) {
		// Each set leaks its assembled value into the workspace, so repeatedly
		// rewriting the same header exhausts the 256KB workspace even though the
		// header itself stays small.
		chunk := strings.Repeat("a", 4000)
		body := strings.Repeat(`set req.http.A = "`+chunk+`";`+"\n", 80)
		vcl := "sub vcl_recv {\n" + body + "}"
		assertInterpreter(t, vcl, context.RecvScope, nil, true)
	})

	t.Run("growing a header leaks every intermediate copy", func(t *testing.T) {
		// This mirrors how the signer builds an accumulator: each append
		// reassembles the whole value, and every leaked intermediate copy
		// counts, so a header that only ever reaches a few KB still overflows.
		chunk := strings.Repeat("a", 1000)
		body := strings.Repeat(`set req.http.A = req.http.A "`+chunk+`";`+"\n", 40)
		vcl := "sub vcl_recv {\n" + body + "}"
		assertInterpreter(t, vcl, context.RecvScope, nil, true)
	})

	t.Run("workspace is not reclaimed across restarts", func(t *testing.T) {
		// A single pass fits, but the header is rebuilt on the restart and the
		// leaked copies accumulate, so the second pass overflows.
		chunk := strings.Repeat("a", 170000)
		vcl := `sub vcl_recv {
			set req.http.Big = "` + chunk + `";
			if (req.restarts == 0) {
				restart;
			}
		}`
		assertInterpreter(t, vcl, context.RecvScope, nil, true)
	})
}

func TestRequestWorkspaceAccounting(t *testing.T) {
	// The probe reads workspace.bytes_free right after the write under test, so it
	// equals the workspace minus the inbound baseline and the write cost. The
	// baseline is the fixed overhead plus the only inbound header the test request
	// carries, Host (localhost).
	baseline := int64(limitations.BaseRequestWorkspaceOverhead) +
		int64(roundUpToPointer(len("Host")+len("localhost")+3))
	free := func(writeCost int64) int64 {
		return int64(limitations.MaxRequestWorkspaceSize) - baseline - writeCost
	}

	tests := []struct {
		name  string
		write string
		free  int64
	}{
		{
			// roundUp8(5 + 5 + 3) = roundUp8(13) = 16
			name:  "bare name plus value plus three, rounded to 8",
			write: `set req.http.X-Foo = "hello";`,
			free:  free(16),
		},
		{
			// The req.http. prefix is not counted: roundUp8(1 + 1 + 3) = 8,
			// not roundUp8(len("req.http.a") + 1) = 16.
			name:  "short header does not pay for the req.http. prefix",
			write: `set req.http.a = "b";`,
			free:  free(8),
		},
		{
			// add charges the appended line the same way: roundUp8(3 + 5 + 3) = 16
			name:  "add charges the appended value",
			write: `add req.http.Via = "proxy";`,
			free:  free(16),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vcl := "sub vcl_recv {\n  " + tt.write + "\n" +
				"  set req.http.Probe = workspace.bytes_free;\n}"
			assertInterpreter(t, vcl, context.RecvScope, map[string]value.Value{
				"req.http.Probe": &value.String{Value: strconv.FormatInt(tt.free, 10)},
			}, false)
		})
	}
}

func TestSubroutineCallTreeLimit(t *testing.T) {
	t.Run("a modest call graph is accepted", func(t *testing.T) {
		vcl := "sub leaf {}\n" +
			"sub helper {\n" + strings.Repeat("  call leaf;\n", 50) + "}\n" +
			"sub vcl_recv {\n  call helper;\n}"
		assertInterpreter(t, vcl, context.RecvScope, nil, false)
	})

	t.Run("an explosive call graph is rejected at init", func(t *testing.T) {
		// helper expands to 200, recv to 200 * (1 + 200) = 40200, over 25000.
		vcl := "sub leaf {}\n" +
			"sub helper {\n" + strings.Repeat("  call leaf;\n", 200) + "}\n" +
			"sub vcl_recv {\n" + strings.Repeat("  call helper;\n", 200) + "}"
		assertInterpreter(t, vcl, context.RecvScope, nil, true)
	})
}
