package http

import (
	"bytes"
	"io"
	"net/http"
)

type Response struct {
	*http.Response
	assigned notSetKeyMap
}

func WrapResponse(r *http.Response) *Response {
	return &Response{
		Response: r,
		assigned: notSetKeyMap{},
	}
}

func (r *Response) Clone() *Response {
	// rewind body reader
	var buf bytes.Buffer
	buf.ReadFrom(r.Body) // nolint: errcheck
	r.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))

	return &Response{
		Response: &http.Response{
			StatusCode:       r.StatusCode,
			Status:           r.Status,
			Proto:            r.Proto,
			ProtoMajor:       r.ProtoMajor,
			ProtoMinor:       r.ProtoMinor,
			Header:           r.Header.Clone(),
			Body:             io.NopCloser(bytes.NewReader(buf.Bytes())),
			ContentLength:    r.ContentLength,
			TransferEncoding: r.TransferEncoding,
			Close:            r.Close,
			Uncompressed:     r.Uncompressed,
			Trailer:          r.Trailer.Clone(),
			TLS:              r.TLS,
		},
		assigned: notSetKeyMap{},
	}
}

func (r *Response) IsAssigned(name string) bool {
	_, v := r.assigned[name]
	return v
}

func (r *Response) Assign(name string) {
	r.assigned[name] = struct{}{}
}

func (r *Response) Unassign(name string) {
	delete(r.assigned, name)
}
