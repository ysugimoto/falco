package interpreter

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/http"
)

var (
	esiIncludeRegex = regexp.MustCompile(`<esi:include\s*src=['"]([^'"]+)['"]\s*/?\s*>`)
	esiRemoveStart  = []byte("<esi:remove>")
	esiRemoveEnd    = []byte("</esi:remove>")
)

func (i *Interpreter) executeESI() error {
	resp := i.ctx.Response
	if resp == nil {
		return exception.System("Client Response is nil")
	}

	var respBody bytes.Buffer
	if _, err := respBody.ReadFrom(resp.Body); err != nil {
		return err
	}

	body := respBody.Bytes()
	req := i.ctx.Request
	ctx := i.ctx.Request.Context()
	var parsed []byte
	for {
		match := esiIncludeRegex.FindSubmatchIndex(body)
		if len(match) == 0 {
			break
		}
		previous := body[0:match[0]]
		src := body[match[2]:match[3]]
		body = body[match[1]:]
		parsed = append(parsed, previous...)

		// resolve inclusion
		cloned := req.Clone(ctx)
		partial, err := executeEsiInclude(ctx, cloned, src)
		if err != nil {
			// If ESI inclusion failed, find <esi:remove> tag and use its nodeText
			index := bytes.Index(body, esiRemoveStart)
			if index == -1 {
				break
			}
			body = body[index+len(esiRemoveStart):]

			// Find </esi:remove> tag
			index = bytes.Index(body, esiRemoveEnd)
			if index == -1 {
				return exception.Runtime(nil, "Syntax error: does not seem to close </esi:remove>")
			}
			parsed = append(parsed, body[0:index]...)
			body = body[index+len(esiRemoveEnd):]
		} else {
			parsed = append(parsed, partial...)
			// If ESI inclusion succeeded, find <esi:remove>...</esi:remove> tag and remove it
			index := bytes.Index(body, esiRemoveStart)
			if index == -1 {
				continue
			}
			body = body[index+len(esiRemoveStart):]
			index = bytes.Index(body, esiRemoveEnd)
			if index == -1 {
				return exception.Runtime(nil, "Syntax error: does not seem to close </esi:remove>")
			}
			body = body[index+len(esiRemoveEnd):]
		}
	}

	// remaining bytes
	if len(body) > 0 {
		parsed = append(parsed, body...)
	}
	resp.Body = io.NopCloser(bytes.NewReader(parsed))
	return nil
}

func executeEsiInclude(ctx context.Context, req *http.Request, includeUrl []byte) ([]byte, error) {
	ctx, timeout := context.WithTimeout(ctx, 10*time.Second)
	defer timeout()

	if err := resolveIncludeURL(req, string(includeUrl)); err != nil {
		return nil, err
	}

	resp, err := http.SendRequest(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func resolveIncludeURL(req *http.Request, path string) error {
	switch {
	case strings.HasPrefix(path, "http://"), strings.HasPrefix(path, "https://"):
		parsed, err := url.Parse(path)
		if err != nil {
			return err
		}
		req.URL = parsed
		req.Header.Set("Host", parsed.Host)
		return nil
	case strings.HasPrefix(path, "/"):
		req.URL.Path = path
		return nil
	default:
		req.URL.Path = filepath.Join(req.URL.Path, path)
		return nil
	}
}
