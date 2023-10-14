package variable

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ysugimoto/falco/interpreter/value"
)

func TestGetRequestHeaderValue(t *testing.T) {
	tests := []struct {
		name   string
		expect string
	}{
		{name: "foo", expect: "bar"},
		{name: "hoge", expect: ""},
		{name: "Text:lorem", expect: "ipsum"},
		{name: "Text:amet", expect: ""},
		{name: "Cookie:foo", expect: "bar"},
		{name: "Cookie:baz", expect: ""},
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("Foo", "bar")
	req.Header.Add("Text", "lorem=ipsum")
	req.Header.Add("Text", "dolor=sit")
	req.Header.Set("Cookie", "foo=bar")

	for _, tt := range tests {
		ret := getRequestHeaderValue(req, tt.name)
		if ret.Value != tt.expect {
			t.Errorf("Return value unmatch, expect=%s, got=%s", tt.expect, ret.Value)
		}
	}

}
func TestGetReponseHeaderValue(t *testing.T) {
	tests := []struct {
		name   string
		expect string
	}{
		{name: "foo", expect: "bar"},
		{name: "hoge", expect: ""},
		{name: "Text:lorem", expect: "ipsum"},
		{name: "Text:amet", expect: ""},
	}
	header := http.Header{}
	header.Set("Foo", "bar")
	header.Add("Text", "lorem=ipsum")
	header.Add("Text", "dolor=sit")
	header.Set("Cookie", "foo=bar")
	resp := &http.Response{Header: header}

	for _, tt := range tests {
		ret := getResponseHeaderValue(resp, tt.name)
		if ret.Value != tt.expect {
			t.Errorf("Return value unmatch, expect=%s, got=%s", tt.expect, ret.Value)
		}
	}

}
func TestSetRequestHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "foo", value: "bar"},
		{name: "Text:lorem", value: "ipsum"},
		{name: "Cookie:foo", value: "bar"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
		setRequestHeaderValue(req, tt.name, &value.String{Value: tt.value})
		ret := getRequestHeaderValue(req, tt.name)
		if ret.Value != tt.value {
			t.Errorf("Return value unmatch, expect=%s, got=%s", tt.value, ret.Value)
		}
	}

}
func TestSetResponseHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "foo", value: "bar"},
		{name: "Text:lorem", value: "ipsum"},
	}

	for _, tt := range tests {
		resp := &http.Response{Header: http.Header{}}
		setResponseHeaderValue(resp, tt.name, &value.String{Value: tt.value})
		ret := getResponseHeaderValue(resp, tt.name)
		if ret.Value != tt.value {
			t.Errorf("Return value unmatch, expect=%s, got=%s", tt.value, ret.Value)
		}
	}

}
func TestUnsetRequestHeaderValue(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "foo"},
		{name: "hoge"},
		{name: "Text:lorem"},
		{name: "Text:amet"},
		{name: "Cookie:foo"},
		{name: "Cookie:baz"},
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("Foo", "bar")
	req.Header.Add("Text", "lorem=ipsum")
	req.Header.Add("Text", "dolor=sit")
	req.Header.Set("Cookie", "foo=bar")

	for _, tt := range tests {
		unsetRequestHeaderValue(req, tt.name)
		ret := getRequestHeaderValue(req, tt.name)
		if ret.Value != "" {
			t.Errorf("Unset value still not empty, got=%s", ret.Value)
		}
	}
}

func TestUnsetResponseHeaderValue(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "foo"},
		{name: "hoge"},
		{name: "Text:lorem"},
		{name: "Text:amet"},
	}
	header := http.Header{}
	header.Set("Foo", "bar")
	header.Add("Text", "lorem=ipsum")
	header.Add("Text", "dolor=sit")
	resp := &http.Response{Header: header}

	for _, tt := range tests {
		unsetResponseHeaderValue(resp, tt.name)
		ret := getResponseHeaderValue(resp, tt.name)
		if ret.Value != "" {
			t.Errorf("Unset value still not empty, got=%s", ret.Value)
		}
	}
}

func TestRemoveCookieByName(t *testing.T) {
	tests := []struct {
		name   string
		expect int
	}{
		{name: "foo", expect: 1},
		{name: "hoge", expect: 2},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
		req.Header.Add("Cookie", "foo=bar")
		req.Header.Add("Cookie", "cat=meow")
		removeCookieByName(req, tt.name)
		if len(req.Cookies()) != tt.expect {
			t.Errorf("Cookie will not deleted for %s", tt.name)
		}
	}
}
