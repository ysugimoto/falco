package interpreter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gobwas/glob"
	"github.com/k0kubun/pp"
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/config"
	icontext "github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/limitations"
	"github.com/ysugimoto/falco/interpreter/value"
	"github.com/ysugimoto/falco/interpreter/variable"
)

const HTTPS_SCHEME = "https"

func getOverrideBackend(ctx *icontext.Context, backendName string) (*config.OverrideBackend, error) {
	for key, val := range ctx.OverrideBackends {
		p, err := glob.Compile(key)
		if err != nil {
			return nil, exception.System("Invalid glob pattern is provided: %s, %s", key, err)
		}
		if !p.Match(backendName) {
			continue
		}
		return val, nil
	}
	return nil, nil
}

func setupFastlyHeaders(req *http.Request) {
	// Fastly-FF
	// https://www.fastly.com/documentation/reference/http/http-headers/Fastly-FF/#format
	mac := hmac.New(sha256.New, []byte("falco"))
	mac.Write([]byte(variable.FALCO_VIRTUAL_SERVICE_ID))
	hash := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	ff := fmt.Sprintf("%s!%s!%s", hash, variable.FALCO_DATACENTER, variable.FALCO_SERVER_HOSTNAME)
	if req.Header.Get("Fastly-FF") != "" {
		req.Header.Add("Fastly-FF", ","+ff)
	} else {
		req.Header.Set("Fastly-FF", ff)
	}
	// TODO: cdn-loop, fastly-client, fastly-client-ip, x-forwarded-for, x-forwarded-host, x-forwarded-server, x-varnish,
}

func (i *Interpreter) createBackendRequest(ctx *icontext.Context, backend *value.Backend) (*http.Request, error) {
	var port string
	if v, err := i.getBackendProperty(backend.Value.Properties, "port"); err != nil {
		return nil, errors.WithStack(err)
	} else if v != nil {
		port = value.Unwrap[*value.String](v).Value
	}

	// Get override backend host from configuration
	overrideBackend, err := getOverrideBackend(ctx, backend.Value.Name.Value)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// scheme may be overrided by config
	scheme := "http"
	if overrideBackend != nil {
		if overrideBackend.SSL {
			scheme = HTTPS_SCHEME
		}
	} else {
		if v, err := i.getBackendProperty(backend.Value.Properties, "ssl"); err != nil {
			return nil, errors.WithStack(err)
		} else if v != nil {
			if value.Unwrap[*value.Boolean](v).Value {
				scheme = HTTPS_SCHEME
			}
		}
	}

	// host may be overrided by config
	var host string
	if overrideBackend != nil {
		host = overrideBackend.Host
	} else {
		if v, err := i.getBackendProperty(backend.Value.Properties, "host"); err != nil {
			return nil, errors.WithStack(err)
		} else if v != nil {
			host = value.Unwrap[*value.String](v).Value
		} else {
			return nil, exception.Runtime(nil, "Failed to find host for backend %s", backend)
		}
	}

	if port == "" {
		if scheme == HTTPS_SCHEME {
			port = "443"
		} else {
			port = "80"
		}
	}

	url := fmt.Sprintf("%s://%s:%s%s", scheme, host, port, i.ctx.Request.URL.Path)
	query := i.ctx.Request.URL.Query()
	if v := query.Encode(); v != "" {
		url += "?" + v
	}

	req, err := http.NewRequest(
		i.ctx.Request.Method,
		url,
		i.ctx.Request.Body,
	)
	if err != nil {
		return nil, exception.Runtime(nil, "Failed to create backend request: %s", err)
	}
	req.Header = i.ctx.Request.Header.Clone()
	setupFastlyHeaders(req)

	hostHeader, err := i.getOriginHostHeader(backend, host)
	if err != nil {
		return nil, errors.WithStack(err)
	} else if hostHeader != nil {
		req.Header.Set("Host", *hostHeader)
	}
	return req, nil
}

func (i *Interpreter) getOriginHostHeader(backend *value.Backend, defaultHost string) (*string, error) {
	// Check backend is dynamic
	if v, err := i.getBackendProperty(backend.Value.Properties, "dynamic"); err != nil {
		pp.Println("dynamic get error")
		return nil, errors.WithStack(err)
	} else if v != nil && v.Type() == value.BooleanType {
		pp.Println("dynamic boolean")
		// If backend is dynamic, lookup .host_header field value
		if vv, err := i.getBackendProperty(backend.Value.Properties, "host_header"); err != nil {
			return nil, errors.WithStack(err)
		} else if vv != nil && vv.Type() == value.StringType {
			return &value.Unwrap[*value.String](vv).Value, nil
		}
	}

	// Otherwise, check .always_use_host_header is defined
	if v, err := i.getBackendProperty(backend.Value.Properties, "always_use_host_header"); err != nil {
		return nil, errors.WithStack(err)
	} else if v != nil && v.Type() == value.BooleanType {
		if value.Unwrap[*value.Boolean](v).Value {
			return &defaultHost, nil
		}
	}
	return nil, nil
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
	if err := limitations.CheckFastlyRequestLimit(req); err != nil {
		return nil, errors.WithStack(err)
	}

	client := http.DefaultClient
	if req.URL.Scheme == HTTPS_SCHEME {
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.WithStack(errors.New("cannot clone http.DefaultTransport"))
		}

		transport := defaultTransport.Clone()
		transport.TLSClientConfig = &tls.Config{
			ServerName: req.URL.Hostname(),
		}

		client = &http.Client{
			Transport: transport,
		}
	}

	// Debug message
	var suffix string
	// nolint:errcheck
	if overrideBackend, _ := getOverrideBackend(i.ctx, backend.Value.Name.Value); overrideBackend != nil {
		suffix = " (overrided by config)"
	}
	i.Debugger.Message(
		fmt.Sprintf("Fetching backend (%s) %s%s", backend.Value.Name.Value, req.URL.String(), suffix),
	)

	resp, err := client.Do(req)
	if err != nil {
		return nil, exception.Runtime(nil, "Failed to retrieve backend response: %s", err)
	}

	// Debug message
	i.Debugger.Message(
		fmt.Sprintf("Backend (%s) responds status code %d", backend.Value.Name.Value, resp.StatusCode),
	)

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
	// rewind body reader
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
		TLS:              resp.TLS,
	}
}
