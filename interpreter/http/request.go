package http

import (
	"context"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

type Request struct {
	*http.Request
	assigned notSetKeyMap
}

func WrapRequest(r *http.Request) *Request {
	return &Request{
		Request:  r,
		assigned: notSetKeyMap{},
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

func (r *Request) IsAssigned(name string) bool {
	_, v := r.assigned[name]
	return v
}

func (r *Request) Assign(name string) {
	r.assigned[name] = struct{}{}
}

func (r *Request) Unassign(name string) {
	delete(r.assigned, name)
}
