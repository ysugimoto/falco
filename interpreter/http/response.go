package http

import (
	"bytes"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

// Interpreter HTTP response representation
type Response struct {
	// Same as http.Response struct but only specify http-related fields
	Status           string
	StatusCode       int
	Proto            string
	ProtoMajor       int
	ProtoMinor       int
	ContentLength    int64
	TransferEncoding []string
	Uncompressed     bool

	// Header uses interpreter's Header struct
	Trailer Header
	Header  Header

	// Copied request body
	Body io.ReadCloser
}

func (r *Response) Clone() (*Response, error) {
	resp := &Response{
		Status:           r.Status,
		StatusCode:       r.StatusCode,
		Proto:            r.Proto,
		ProtoMajor:       r.ProtoMajor,
		ProtoMinor:       r.ProtoMinor,
		ContentLength:    r.ContentLength,
		Uncompressed:     r.Uncompressed,
		TransferEncoding: make([]string, len(r.TransferEncoding)),

		Trailer: r.Trailer.Clone(),
		Header:  r.Header.Clone(),
	}
	copy(resp.TransferEncoding, r.TransferEncoding)

	// Copy response body
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r.Body); err != nil {
		return nil, errors.WithStack(err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	return resp, nil
}

func ToGoHttpResponse(r *Response) (*http.Response, error) {
	resp := &http.Response{
		StatusCode:       r.StatusCode,
		Status:           r.Status,
		Proto:            r.Proto,
		ProtoMajor:       r.ProtoMajor,
		ProtoMinor:       r.ProtoMinor,
		ContentLength:    r.ContentLength,
		Uncompressed:     r.Uncompressed,
		TransferEncoding: make([]string, len(r.TransferEncoding)),

		Trailer: ToGoHttpHeader(r.Trailer),
		Header:  ToGoHttpHeader(r.Header),
	}
	copy(resp.TransferEncoding, r.TransferEncoding)

	// Copy response body
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r.Body); err != nil {
		return nil, errors.WithStack(err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	return resp, nil
}

func FromGoHttpResponse(r *http.Response) (*Response, error) {
	resp := &Response{
		Status:           r.Status,
		StatusCode:       r.StatusCode,
		Proto:            r.Proto,
		ProtoMajor:       r.ProtoMajor,
		ProtoMinor:       r.ProtoMinor,
		ContentLength:    r.ContentLength,
		Uncompressed:     r.Uncompressed,
		TransferEncoding: make([]string, len(r.TransferEncoding)),

		Trailer: FromGoHttpHeader(r.Trailer),
		Header:  FromGoHttpHeader(r.Header),
	}
	copy(resp.TransferEncoding, r.TransferEncoding)

	// Copy response body
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r.Body); err != nil {
		return nil, errors.WithStack(err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	return resp, nil
}
