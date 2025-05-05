// http package aims to extend golang's http package.
// On processing http related things by VCL, some go's zero value is incovenient
// for dietinguishing whether notset or empty.
// So that this package wraps origin http.Request/http.Response struct
// in order to attach additional convenient field for certail VCL processing.

package http

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/exception"
)

const TimeFormat = http.TimeFormat

// var (
// 	DefaultClient    = http.DefaultClient
// 	DefaultTransport = http.DefaultTransport
// )

// type (
// 	Client = http.Client
// )

type notSetKeyMap map[string]struct{}

func (m notSetKeyMap) Exists(key string) bool {
	_, ok := m[key]
	return ok
}

func CreateCookie(key, value string) *http.Cookie {
	h := http.Header{}
	h.Add("Cookie", fmt.Sprintf("%s=%s", key, value))
	rr := http.Request{Header: h}
	c, _ := rr.Cookie(key) // nolint:errcheck
	return c
}

func SendRequest(req *Request) (*Response, error) {
	client := http.DefaultClient
	if req.URL.Scheme == "https" {
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

	resp, err := client.Do(req.Request)
	if err != nil {
		return nil, exception.Runtime(nil, "Failed to retrieve backend response: %s", err)
	}
	return WrapResponse(resp), nil
}
