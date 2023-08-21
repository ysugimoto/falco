package interpreter

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
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
	MaxReponseHeaderCount     = 96
	MaxRequestBodyPayloadSize = 8 * KB

	// Surrogate key limitations but actually don't check these
	MaxSurrogateKeySize       = 1 * KB
	MaxSurrogateKeyHeaderSize = 1 * KB

	// VCL limitations
	MaxCustomVCLFileSize = 1 * MB
	MaxVarnishRestarts   = 3
	MaxLogLineSize       = 16 * KB

	// Increasable limitations by contacting Fastly support
	// These are defaults, you can override by configuration
	MaxACLCounts     = 1000
	MaxBackendCounts = 5
)

func checkFastlyVCLLimitation(vcl string) error {
	if len([]byte(vcl)) > MaxCustomVCLFileSize {
		return exception.System(
			"Overflow custom VCL file size limitation of %d",
			MaxCustomVCLFileSize,
		)
	}
	return nil
}

func checkFastlyResourceLimit(ctx *context.Context) error {
	maxBackends := MaxBackendCounts
	if ctx.OverrideMaxBackends > maxBackends {
		maxBackends = ctx.OverrideMaxBackends
	}
	if len(ctx.Backends) > maxBackends {
		return exception.System("Max backend count of %d exceeded", maxBackends)
	}
	maxAcls := MaxACLCounts
	if ctx.OverrideMaxAcls > maxAcls {
		maxAcls = ctx.OverrideMaxAcls
	}
	if len(ctx.Acls) > maxAcls {
		return exception.System("Max ACL count of %d exceeded", maxAcls)
	}

	return nil
}

// Validate limitation for the request
func checkFastlyRequestLimit(req *http.Request) error {
	if len([]byte(req.URL.String())) > MaxURLSize {
		return exception.System(
			"URL size is limited under the %d bytes",
			MaxURLSize,
		)
	}

	var cookieSize int
	for _, c := range req.Cookies() {
		cookieSize += len([]byte(c.Raw))
		// If max cookie size is greater than limitation, remove cookit header
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
			[]byte(fmt.Sprintf("%s: %s\n", key, strings.Join(values, ", "))),
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
	if req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch {
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
func checkFastlyResponseLimit(resp *http.Response) error {
	var headerSize, headerCount int
	for key, values := range resp.Header {
		headerSize += len(
			[]byte(fmt.Sprintf("%s: %s\n", key, strings.Join(values, ", "))),
		)
		if headerSize > MaxRequestHeaderSize {
			return exception.System(
				"Overflow response header size limitation of %d bytes",
				MaxRequestHeaderSize,
			)
		}
		headerCount++
		if headerCount > MaxRequestHeaderCount {
			return exception.System(
				"Overflow response header count limitation of %d",
				MaxRequestHeaderCount,
			)
		}
	}

	return nil
}
