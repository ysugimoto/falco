package interpreter

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"crypto/tls"
	"net/http"

	_ "github.com/k0kubun/pp"
	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/value"
)

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
			scheme = "https"
		}
	}
	host, err := i.getBackendProperty(backend.Value.Properties, "host")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if port == "" {
		if scheme == "https" {
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

	req, err := http.NewRequestWithContext(
		i.ctx.Request.Context(),
		i.ctx.Request.Method,
		url,
		i.ctx.Request.Body,
	)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req.Header = i.ctx.Request.Header.Clone()
	return req, nil
}

func (i *Interpreter) sendBackendRequest() (*http.Response, error) {
	req := i.ctx.BackendRequest
	client := http.DefaultClient
	if req.URL.Scheme == "https" {
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
		return nil, errors.WithStack(err)
	}

	// read all response body to supress memory leak
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
	buf.ReadFrom(resp.Body)
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
