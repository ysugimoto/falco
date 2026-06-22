package limitations

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	ghttp "net/http"
	"sort"
	"strings"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/http"
)

// Units
const (
	KB = 1024
	MB = 1024 * 1024
)

// Consolidate Fastly's limitation checks
// See https://docs.fastly.com/en/guides/resource-limits#request-and-response-limits
const (
	// Request and Response limitations
	MaxURLSize                = 8 * KB
	MaxCookieSize             = 32 * KB
	MaxRequestHeaderSize      = 69 * KB
	MaxResponseHeaderSize     = 69 * KB
	MaxRequestHeaderCount     = 96
	MaxResponseHeaderCount    = 96
	MaxRequestBodyPayloadSize = 8 * KB

	// Surrogate key limitations but actually don't check these
	MaxSurrogateKeySize       = 1 * KB
	MaxSurrogateKeyHeaderSize = 1 * KB

	// VCL limitations
	MaxCustomVCLFileSize = 1 * MB
	MaxVarnishRestarts   = 3
	MaxLogLineSize       = 16 * KB

	// MaxSubroutineCallTree is the ceiling Fastly enforces on the fully inlined
	// subroutine call graph. The cost of a subroutine is the sum, over each of
	// its `call` statements, of one plus the callee's own cost, so nested calls
	// multiply. Past this, Fastly rejects activation with "Too many sub calls".
	MaxSubroutineCallTree = 25000

	// MaxRequestWorkspaceSize is the size of the per-request workspace. Request
	// headers are assembled into this workspace and the previous copy is never
	// reclaimed, even across restarts, so a VCL that rewrites a header many
	// times eventually overflows it and Fastly returns "503 Header overflow".
	MaxRequestWorkspaceSize = 256 * KB

	// BaseRequestWorkspaceOverhead approximates what Fastly has already consumed
	// before any user VCL runs (internal structures and injected headers). A
	// production service shows ~8.5KB, varying by POP and connection, so we charge
	// a conservative 10KB on top of the inbound headers we can see.
	BaseRequestWorkspaceOverhead = 10 * KB

	// Increasable limitations by contacting Fastly support
	// These are defaults, you can override by configuration
	MaxACLCounts     = 1000
	MaxBackendCounts = 5
)

func CheckFastlyVCLLimitation(vcl string) error {
	if len([]byte(vcl)) > MaxCustomVCLFileSize {
		return exception.System(
			"Overflow custom VCL file size limitation of %d",
			MaxCustomVCLFileSize,
		)
	}
	return nil
}

// CheckFastlyCallTreeLimit emulates Fastly's compile-time check on the fully
// inlined subroutine call graph. Fastly inlines every `call` statement, so a
// subroutine that calls another many times multiplies the callee's whole
// subtree. When the expansion of any subroutine exceeds MaxSubroutineCallTree,
// activation fails with "Too many sub calls".
func CheckFastlyCallTreeLimit(ctx *context.Context) error {
	subroutines := make(
		map[string]*ast.SubroutineDeclaration,
		len(ctx.Subroutines)+len(ctx.SubroutineFunctions),
	)
	maps.Copy(subroutines, ctx.Subroutines)
	maps.Copy(subroutines, ctx.SubroutineFunctions)

	costs := make(map[string]int, len(subroutines))
	visiting := make(map[string]bool, len(subroutines))

	var cost func(name string) int
	cost = func(name string) int {
		if c, ok := costs[name]; ok {
			return c
		}
		sub, ok := subroutines[name]
		if !ok {
			return 0
		}
		// Guard against recursive VCL (which Fastly rejects anyway) so the walk
		// always terminates; the interpreter reports the recursion separately
		// through its runtime call-stack guard.
		if visiting[name] {
			return 0
		}
		visiting[name] = true
		var total int
		for _, call := range collectCallStatements(sub.Block) {
			total += 1 + cost(call.Subroutine.Value)
		}
		visiting[name] = false
		costs[name] = total
		return total
	}

	// Report deterministically by visiting subroutines in name order.
	names := make([]string, 0, len(subroutines))
	for name := range subroutines {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if c := cost(name); c > MaxSubroutineCallTree {
			return exception.Runtime(
				&subroutines[name].GetMeta().Token,
				"Too many sub calls: subroutine %s expands to %d calls, exceeding the limit of %d",
				name, c, MaxSubroutineCallTree,
			)
		}
	}
	return nil
}

// collectCallStatements returns every `call` statement reachable inside a
// subroutine block, descending into nested if/else and switch blocks.
func collectCallStatements(block *ast.BlockStatement) []*ast.CallStatement {
	if block == nil {
		return nil
	}
	var calls []*ast.CallStatement
	walkCallStatements(block.Statements, &calls)
	return calls
}

func walkCallStatements(statements []ast.Statement, calls *[]*ast.CallStatement) {
	for _, stmt := range statements {
		switch t := stmt.(type) {
		case *ast.CallStatement:
			*calls = append(*calls, t)
		case *ast.BlockStatement:
			walkCallStatements(t.Statements, calls)
		case *ast.IfStatement:
			walkIfCallStatements(t, calls)
		case *ast.SwitchStatement:
			for _, c := range t.Cases {
				walkCallStatements(c.Statements, calls)
			}
		}
	}
}

func walkIfCallStatements(stmt *ast.IfStatement, calls *[]*ast.CallStatement) {
	if stmt.Consequence != nil {
		walkCallStatements(stmt.Consequence.Statements, calls)
	}
	for _, another := range stmt.Another {
		walkIfCallStatements(another, calls)
	}
	if stmt.Alternative != nil && stmt.Alternative.Consequence != nil {
		walkCallStatements(stmt.Alternative.Consequence.Statements, calls)
	}
}

func CheckFastlyResourceLimit(ctx *context.Context) error {
	maxBackends := max(ctx.OverrideMaxBackends, MaxBackendCounts)
	if len(ctx.Backends) > maxBackends {
		return exception.System(
			"Max backend count of %d exceeded. Provide --max_backends option or add configuration file to increase",
			maxBackends,
		)
	}
	maxAcls := max(ctx.OverrideMaxAcls, MaxACLCounts)
	if len(ctx.Acls) > maxAcls {
		return exception.System(
			"Max ACL count of %d exceeded. Provide --max_acls option or add configuration file to increase",
			maxAcls,
		)
	}

	return nil
}

// Validate limitation for the request
func CheckFastlyRequestLimit(req *http.Request) error {
	if len([]byte(req.URL.String())) > MaxURLSize {
		return exception.System(
			"URL size is limited under the %d bytes",
			MaxURLSize,
		)
	}

	var cookieSize int
	for _, c := range req.Cookies() {
		cookieSize += len([]byte(c.Raw))
		// If max cookie size is greater than limitation, remove cookie header
		// and add overflow header
		if cookieSize > MaxCookieSize {
			req.Header.Del("Cookie")
			req.Header.Set("Fastly-Cookie-Overflow", "1")
			break
		}
	}

	var headerSize, headerCount int
	for key, values := range req.Header {
		headerSize += len(
			fmt.Appendf([]byte{}, "%s: %s\n", key, strings.Join(values, ", ")),
		)
		if headerSize > MaxRequestHeaderSize {
			return exception.System(
				"Overflow request header size limitation of %d bytes",
				MaxRequestHeaderSize,
			)
		}
		headerCount++
		if headerCount > MaxRequestHeaderCount {
			return exception.System(
				"Overflow request header count limitation of %d",
				MaxRequestHeaderCount,
			)
		}
	}

	// Request body size check
	if req.Method == ghttp.MethodPost || req.Method == ghttp.MethodPut || req.Method == ghttp.MethodPatch {
		var body bytes.Buffer
		// We don't trust Content-Length header value, check actual body size
		if _, err := body.ReadFrom(req.Body); err == nil {
			// If payload size is greater than limitation, truncate the body
			if len(body.Bytes()) > MaxRequestBodyPayloadSize {
				req.Body = io.NopCloser(strings.NewReader(""))
			} else {
				// Rewind request body
				req.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
			}
		}
	}

	return nil
}

// Validate limitation for the response
func CheckFastlyResponseLimit(resp *http.Response) error {
	var headerSize, headerCount int
	for key, values := range resp.Header {
		headerSize += len(
			fmt.Appendf([]byte{}, "%s: %s\n", key, strings.Join(values, ", ")),
		)
		if headerSize > MaxResponseHeaderSize {
			return exception.System(
				"Overflow response header size limitation of %d bytes",
				MaxResponseHeaderSize,
			)
		}
		headerCount++
		if headerCount > MaxResponseHeaderCount {
			return exception.System(
				"Overflow response header count limitation of %d",
				MaxResponseHeaderCount,
			)
		}
	}

	return nil
}
