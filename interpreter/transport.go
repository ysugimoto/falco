package interpreter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"crypto/tls"
	"net/http"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/value"
)

const headerOverflowMaxSize = 69 * 1024 // 69KB
const HTTPS_SCHEME = "https"

func (i *Interpreter) createBackendRequest(backend *value.Backend) (*http.Request, error) {
	var port string
	if v, err := i.getBackendProperty(backend.Value.Properties, "port"); err != nil {
		return nil, errors.WithStack(err)
	} else if v != nil {
		port = value.Unwrap[*value.String](v).Value
	}

	scheme := "http"
	if v, err := i.getBackendProperty(backend.Value.Properties, "ssl"); err != nil {
		return nil, errors.WithStack(err)
	} else if v != nil {
		if value.Unwrap[*value.Boolean](v).Value {
			scheme = HTTPS_SCHEME
		}
	}
	host, err := i.getBackendProperty(backend.Value.Properties, "host")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	alwaysHost, err := i.getBackendProperty(backend.Value.Properties, "always_use_host_header")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if port == "" {
		if scheme == HTTPS_SCHEME {
			port = "443"
		} else {
			port = "80"
		}
	}

	url := fmt.Sprintf(
		"%s://%s:%s%s",
		scheme,
		value.Unwrap[*value.String](host).Value,
		port,
		i.ctx.Request.URL.Path,
	)
	query := i.ctx.Request.URL.Query()
	if v := query.Encode(); v != "" {
		url += "?" + v
	}

	// Debug message
	i.Debugger.Message(fmt.Sprintf("Fetching backend (%s) %s", backend.Value.Name.Value, url))

	req, err := http.NewRequest(
		i.ctx.Request.Method,
		url,
		i.ctx.Request.Body,
	)
	if err != nil {
		return nil, exception.Runtime(nil, "Failed to create backend request: %s", err)
	}
	req.Header = i.ctx.Request.Header.Clone()

	alwaysUserHostHeader := false
	if alwaysHost != nil {
		alwaysUserHostHeader = value.Unwrap[*value.Boolean](alwaysHost).Value
	}
	if alwaysUserHostHeader {
		req.Header.Set("Host", value.Unwrap[*value.String](host).Value)
	}
	return req, nil
}

func (i *Interpreter) sendBackendRequest(backend *value.Backend) (*http.Response, error) {
	fbt, err := i.getBackendProperty(backend.Value.Properties, "first_byte_timeout")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	firstByteTimeout := 15 * time.Second
	if fbt != nil {
		firstByteTimeout = value.Unwrap[*value.RTime](fbt).Value
	}

	ctx, timeout := context.WithTimeout(i.ctx.Request.Context(), firstByteTimeout)
	defer timeout()

	req := i.ctx.BackendRequest.Clone(ctx)

	// Check Fastly limitations
	if err := checkFastlyRequestLimit(req); err != nil {
		return nil, errors.WithStack(err)
	}

	client := http.DefaultClient
	if req.URL.Scheme == HTTPS_SCHEME {
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					ServerName: req.URL.Hostname(),
				},
			},
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, exception.Runtime(nil, "Failed to retrieve backend response: %s", err)
	}

	// Debug message
	i.Debugger.Message(fmt.Sprintf("Backend (%s) responds status code %d", backend.Value.Name.Value, resp.StatusCode))

	// read all response body to suppress memory leak
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(resp.Body); err != nil {
		return nil, errors.WithStack(err)
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	return resp, nil
}

func (i *Interpreter) getBackendProperty(props []*ast.BackendProperty, key string) (value.Value, error) {
	var prop ast.Expression
	for _, v := range props {
		if v.Key.Value != key {
			continue
		}
		prop = v.Value
		break
	}
	if prop == nil {
		return nil, nil
	}

	val, err := i.ProcessExpression(prop, false)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return val, nil
}

func (i *Interpreter) cloneResponse(resp *http.Response) *http.Response {
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body) // nolint: errcheck
	resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))

	return &http.Response{
		StatusCode:       resp.StatusCode,
		Status:           resp.Status,
		Proto:            resp.Proto,
		ProtoMajor:       resp.ProtoMajor,
		ProtoMinor:       resp.ProtoMinor,
		Header:           resp.Header.Clone(),
		Body:             io.NopCloser(bytes.NewReader(buf.Bytes())),
		ContentLength:    resp.ContentLength,
		TransferEncoding: resp.TransferEncoding,
		Close:            resp.Close,
		Uncompressed:     resp.Uncompressed,
		Trailer:          resp.Trailer.Clone(),
		Request:          resp.Request.Clone(context.Background()),
		TLS:              resp.TLS,
	}
}
