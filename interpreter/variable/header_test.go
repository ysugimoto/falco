package variable

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestGetRequestHeaderValue(t *testing.T) {
	tests := []struct {
		name   string
		expect *value.String
	}{
		{name: "foo", expect: &value.String{Value: "bar"}},
		{name: "hoge", expect: &value.String{IsNotSet: true}},
		{name: "Text:lorem", expect: &value.String{Value: "ipsum"}},
		{name: "Text:amet", expect: &value.String{IsNotSet: true}},
		{name: "Cookie:foo", expect: &value.String{Value: "bar"}},
		{name: "Cookie:baz", expect: &value.String{IsNotSet: true}},
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("Foo", "bar")
	req.Header.Add("Text", "lorem=ipsum")
	req.Header.Add("Text", "dolor=sit")
	req.Header.Set("Cookie", "foo=bar")

	for _, tt := range tests {
		ret := getRequestHeaderValue(req, tt.name)
		if diff := cmp.Diff(ret, tt.expect); diff != "" {
			t.Errorf("Return value unmatch, diff=%s", diff)
		}
	}

}
func TestGetReponseHeaderValue(t *testing.T) {
	tests := []struct {
		name   string
		expect *value.String
	}{
		{name: "foo", expect: &value.String{Value: "bar"}},
		{name: "hoge", expect: &value.String{IsNotSet: true}},
		{name: "Text:lorem", expect: &value.String{Value: "ipsum"}},
		{name: "Text:amet", expect: &value.String{IsNotSet: true}},
	}
	header := http.Header{}
	header.Set("Foo", "bar")
	header.Add("Text", "lorem=ipsum")
	header.Add("Text", "dolor=sit")
	header.Set("Cookie", "foo=bar")
	resp := &http.Response{Header: header}

	for _, tt := range tests {
		ret := getResponseHeaderValue(resp, tt.name)
		if diff := cmp.Diff(ret, tt.expect); diff != "" {
			t.Errorf("Return value unmatch, diff=%s", diff)
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
		if diff := cmp.Diff(ret, &value.String{IsNotSet: true}); diff != "" {
			t.Errorf("Unset value still not empty, diff=%s", diff)
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
		if diff := cmp.Diff(ret, &value.String{IsNotSet: true}); diff != "" {
			t.Errorf("Unset value still not empty, diff=%s", diff)
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
