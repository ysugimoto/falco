package process

import (
	"net/http"
	"strings"
)

type HttpFlow struct {
	Method     string            `json:"method,omitempty"`
	Host       string            `json:"host,omitempty"`
	URL        string            `json:"url,omitempty"`
	Headers    map[string]string `json:"headers"`
	StatusCode int               `json:"status_code,omitempty"`
	StatusText string            `json:"status_text,omitempty"`
}

func newFlowRequest(req *http.Request) *HttpFlow {
	flow := &HttpFlow{
		Method:  req.Method,
		Host:    req.URL.Hostname(),
		Headers: make(map[string]string),
	}

	flow.URL = req.URL.Path
	if req.URL.RawQuery != "" {
		flow.URL += "?" + req.URL.RawQuery
	}

	for key, values := range req.Header {
		flow.Headers[strings.ToLower(key)] = strings.Join(values, ", ")
	}

	return flow
}

func newFlowResponse(resp *http.Response) *HttpFlow {
	flow := &HttpFlow{
		Headers:    make(map[string]string),
		StatusCode: resp.StatusCode,
		StatusText: resp.Status,
	}

	for key, values := range resp.Header {
		flow.Headers[strings.ToLower(key)] = strings.Join(values, ", ")
	}

	return flow
}
