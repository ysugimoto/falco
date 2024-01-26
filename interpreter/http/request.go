package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Interpreter HTTP request representation
type Request struct {
	// Same as http.Request struct but only specify request-related fields
	Method     string
	Proto      string
	ProtoMajor int
	ProtoMinor int
	Host       string
	RemoteAddr string
	RequestURI string
	URL        *url.URL
	TLS        *tls.ConnectionState

	// context is private in http.Request but we use as public
	Context context.Context

	// Header uses interpreter's Header struct
	Header Header

	// Copied request body
	Body io.ReadCloser
}

func NewRequest(method, url string, body io.Reader) (*Request, error) {
	return NewRequestWithContext(context.Background(), method, url, body)
}

func NewRequestWithContext(ctx context.Context, method, requestUrl string, body io.Reader) (*Request, error) {
	u, err := url.Parse(requestUrl)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req := &Request{
		Method:     method,
		Proto:      "1.0",
		ProtoMajor: 1,
		ProtoMinor: 0,
		Host:       u.Host,
		RequestURI: requestUrl,
		Context:    ctx,
		URL:        u,
		Body:       io.NopCloser(body),
		Header:     Header{},
	}
	req.Header.Set("Host", &value.String{Value: u.Host})
	return req, nil
}

func (r *Request) Clone() (*Request, error) {
	req := &Request{
		Method:     r.Method,
		Proto:      r.Proto,
		ProtoMajor: r.ProtoMajor,
		ProtoMinor: r.ProtoMinor,
		Host:       r.Host,
		RemoteAddr: r.RemoteAddr,
		RequestURI: r.RequestURI,
		Context:    r.Context,
		TLS:        r.TLS,
	}
	// Copy URL
	req.URL = &url.URL{
		Scheme:      r.URL.Scheme,
		Opaque:      r.URL.Opaque,
		Host:        r.URL.Host,
		Path:        r.URL.Path,
		RawPath:     r.URL.RawPath,
		OmitHost:    r.URL.OmitHost,
		ForceQuery:  r.URL.ForceQuery,
		RawQuery:    r.URL.RawQuery,
		Fragment:    r.URL.Fragment,
		RawFragment: r.URL.RawFragment,
	}

	// Clone HttpHeader
	req.Header = r.Header.Clone()

	// Copy request body
	if r.Body != nil {
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r.Body); err != nil {
			return nil, errors.WithStack(err)
		}
		req.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	}
	return req, nil
}

func ToGoHttpRequest(r *Request) (*http.Request, error) {
	req, err := http.NewRequest(
		r.Method,
		r.URL.String(),
		r.Body,
	)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	req.Header = ToGoHttpHeader(r.Header)
	return req, nil
}

func FromGoHttpRequest(r *http.Request) (*Request, error) {
	req := &Request{
		Method:     r.Method,
		Proto:      r.Proto,
		ProtoMajor: r.ProtoMajor,
		ProtoMinor: r.ProtoMinor,
		Host:       r.Host,
		RemoteAddr: r.RemoteAddr,
		RequestURI: r.RequestURI,
		Context:    r.Context(),
		TLS:        r.TLS,
	}
	// Copy URL
	req.URL = &url.URL{
		Scheme:      r.URL.Scheme,
		Opaque:      r.URL.Opaque,
		Host:        r.URL.Host,
		Path:        r.URL.Path,
		RawPath:     r.URL.RawPath,
		OmitHost:    r.URL.OmitHost,
		ForceQuery:  r.URL.ForceQuery,
		RawQuery:    r.URL.RawQuery,
		Fragment:    r.URL.Fragment,
		RawFragment: r.URL.RawFragment,
	}

	// Convert HttpHeader
	req.Header = FromGoHttpHeader(r.Header)

	// Copy request body
	if r.Body != nil {
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r.Body); err != nil {
			return nil, errors.WithStack(err)
		}
		req.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	}
	return req, nil
}
