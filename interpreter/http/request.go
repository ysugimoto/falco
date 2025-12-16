package http

import (
	"context"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

type Request struct {
	*http.Request
	headerKeyStore
}

func WrapRequest(r *http.Request) *Request {
	return &Request{
		r,
		headerKeyStore{},
	}
}

func NewRequest(method, url string, body io.Reader) (*Request, error) {
	r, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return WrapRequest(r), nil
}

func (r *Request) Clone(c context.Context) *Request {
	return WrapRequest(r.Request.Clone(c))
}

func (r *Request) WithContext(c context.Context) *Request {
	return WrapRequest(r.Request.WithContext(c))
}
