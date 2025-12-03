// http package aims to extend golang's http package.
// On processing http related things by VCL, some go's zero value is incovenient
// for dietinguishing whether the header value is notset or empty.
// So that this package wraps original http.Request/http.Response struct
// in order to attach additional convenient field for certain VCL processing.

package http

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/exception"
)

// Re-expose http.TimeFormat to this package
const TimeFormat = http.TimeFormat

// CreateCookie create simple key-value cookie using http header.
func CreateCookie(key, value string) *http.Cookie {
	h := http.Header{}
	h.Add("Cookie", fmt.Sprintf("%s=%s", key, value))
	rr := http.Request{Header: h}
	c, _ := rr.Cookie(key) // nolint:errcheck
	return c
}

// SendRequest sends HTTP request from Request
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

// Fastly VCL explicitly distinguish empty value of HTTP header as empty or notset,
// but Golang's http.Header struct cannot distinguish it because if we retrieve header value
// through the `header.Get(key)` returns empty string even header is notset.
// In order to follow the Faslty behavior, we need to store the header is actually assigned in this map
// and check key existence whether header value is empty or notset.
type headerKeyStore map[string]struct{}

// Distinguish whether header is actually assigned or not
func (h headerKeyStore) IsAssigned(name string) bool {
	_, v := h[name]
	return v
}

func (h headerKeyStore) Assign(name string) {
	h[name] = struct{}{}
}

func (h headerKeyStore) Unassign(name string) {
	delete(h, name)
}
