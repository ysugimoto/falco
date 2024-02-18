package transport

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/pkg/errors"
	flchttp "github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/limitations"
)

// Send proxy request to specific origin
func Send(r *flchttp.Request, timeout time.Duration) (*flchttp.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Check Fastly limitations
	if err := limitations.CheckFastlyRequestLimit(r); err != nil {
		return nil, errors.WithStack(err)
	}

	req, err := flchttp.ToGoHttpRequest(r)
	if err != nil {
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
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if v, err := flchttp.FromGoHttpResponse(resp); err != nil {
		return nil, errors.WithStack(err)
	} else {
		return v, nil
	}
}
