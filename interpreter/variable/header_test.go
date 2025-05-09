package variable

import (
	ghttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/http"
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
	req := http.WrapRequest(
		httptest.NewRequest(ghttp.MethodGet, "http://localhost", nil),
	)
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
	header := ghttp.Header{}
	header.Set("Foo", "bar")
	header.Add("Text", "lorem=ipsum")
	header.Add("Text", "dolor=sit")
	header.Set("Cookie", "foo=bar")
	resp := http.WrapResponse(&ghttp.Response{Header: header})

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
		req := http.WrapRequest(
			httptest.NewRequest(ghttp.MethodGet, "http://localhost", nil),
		)
		setRequestHeaderValue(req, tt.name, &value.String{Value: tt.value})
		ret := getRequestHeaderValue(req, tt.name)
		if ret.Value != tt.value {
			t.Errorf("Return value unmatch, expect=%s, got=%s", tt.value, ret.Value)
		}
	}

}

func TestSetRequestHeaderValueOverwrite(t *testing.T) {
	req := http.WrapRequest(
		httptest.NewRequest(ghttp.MethodGet, "http://localhost", nil),
	)
	setRequestHeaderValue(req, "Foo:abc", &value.String{Value: "123"})
	setRequestHeaderValue(req, "Foo:bar", &value.String{Value: "baz"})
	setRequestHeaderValue(req, "Foo:bar", &value.String{Value: "snafu"})

	ret := getRequestHeaderValue(req, "Foo:bar")
	if ret.Value != "snafu" {
		t.Errorf("Return value unmatch, expect=%s, got=%s", "snafu", ret.Value)
	}

	ret = getRequestHeaderValue(req, "Foo")
	if ret.Value != "abc=123,bar=snafu" {
		t.Errorf("Return value unmatch, expect=%s, got=%s", "abc=123,bar=snafu", ret.Value)
	}

	// Check exact http.Header struct data
	if diff := cmp.Diff(req.Header, ghttp.Header{
		"Foo": []string{"abc=123,bar=snafu"},
	}); diff != "" {
		t.Errorf(diff)
	}
}

func TestSetResponseHeaderValueEmpty(t *testing.T) {
	req := http.WrapRequest(
		httptest.NewRequest(ghttp.MethodGet, "http://localhost", nil),
	)
	// Set empty header values
	setRequestHeaderValue(req, "VARS", &value.String{Value: ""})
	setRequestHeaderValue(req, "VARS:VALUE", &value.String{Value: ""})
	setRequestHeaderValue(req, "VARS:VALUE2", &value.String{Value: ""})

	// Each field value does not have equal signs, only present key name
	ret := getRequestHeaderValue(req, "VARS")
	if ret.Value != "VALUE,VALUE2" {
		t.Errorf("Return value unmatch, expect=%s, got=%s", "VALUE,VALUE2", ret.Value)
	}

	// Overwrite partial key and value
	setRequestHeaderValue(req, "VARS:VALUE", &value.String{Value: "V"})
	ret = getRequestHeaderValue(req, "VARS")
	if ret.Value != "VALUE2,VALUE=V" {
		t.Errorf("Return value unmatch, expect=%s, got=%s", "VALUE2,VALUE=V", ret.Value)
	}

	// Can unset empty key
	unsetRequestHeaderValue(req, "VARS:VALUE2")
	ret = getRequestHeaderValue(req, "VARS")
	if ret.Value != "VALUE=V" {
		t.Errorf("Return value unmatch, expect=%s, got=%s", "VALUE=V", ret.Value)
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
		resp := http.WrapResponse(&ghttp.Response{Header: ghttp.Header{}})
		setResponseHeaderValue(resp, tt.name, &value.String{Value: tt.value})
		ret := getResponseHeaderValue(resp, tt.name)
		if ret.Value != tt.value {
			t.Errorf("Return value unmatch, expect=%s, got=%s", tt.value, ret.Value)
		}
	}

}

func TestSetResponseHeaderValueOverwrite(t *testing.T) {
	resp := http.WrapResponse(&ghttp.Response{Header: ghttp.Header{}})
	setResponseHeaderValue(resp, "Foo:abc", &value.String{Value: "123"})
	setResponseHeaderValue(resp, "Foo:bar", &value.String{Value: "baz"})
	setResponseHeaderValue(resp, "Foo:bar", &value.String{Value: "snafu"})

	ret := getResponseHeaderValue(resp, "Foo:bar")
	if ret.Value != "snafu" {
		t.Errorf("Return value unmatch, expect=%s, got=%s", "snafu", ret.Value)
	}

	ret = getResponseHeaderValue(resp, "Foo")
	if ret.Value != "abc=123,bar=snafu" {
		t.Errorf("Return value unmatch, expect=%s, got=%s", "abc=123,bar=snafu", ret.Value)
	}

	// Check exact http.Header struct data
	if diff := cmp.Diff(resp.Header, ghttp.Header{
		"Foo": []string{"abc=123,bar=snafu"},
	}); diff != "" {
		t.Errorf(diff)
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

	for _, tt := range tests {
		req := http.WrapRequest(
			httptest.NewRequest(ghttp.MethodGet, "http://localhost", nil),
		)
		req.Header.Set("Foo", "bar")
		req.Header.Add("Text", "lorem=ipsum")
		req.Header.Add("Text", "dolor=sit")
		req.Header.Set("Cookie", "foo=bar")

		unsetRequestHeaderValue(req, tt.name)
		ret := getRequestHeaderValue(req, tt.name)
		if diff := cmp.Diff(ret, &value.String{IsNotSet: true}); diff != "" {
			t.Errorf("Unset value still not empty, diff=%s", diff)
		}
	}
}

func TestUnsetRequestHeaderValueWildcard(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		expects map[string]value.Value
	}{
		{
			name: "unset simple wildcard fields",
			key:  "X-*",
			expects: map[string]value.Value{
				"X-SomeHeader-1": &value.String{IsNotSet: true},
				"X-SomeHeader-2": &value.String{IsNotSet: true},
			},
		},
		{
			name: "subfiled wildcard does not be delete",
			key:  "VARS:VALUE*",
			expects: map[string]value.Value{
				"VARS:VALUE1": &value.String{Value: "foo"},
				"VARS:VALUE2": &value.String{Value: "bar"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := http.WrapRequest(httptest.NewRequest(ghttp.MethodGet, "http://localhost", nil))
			req.Header.Set("X-SomeHeader-1", "foo")
			req.Header.Set("X-SomeHeader-2", "bar")
			setRequestHeaderValue(req, "VARS:VALUE1", &value.String{Value: "foo"})
			setRequestHeaderValue(req, "VARS:VALUE2", &value.String{Value: "bar"})

			unsetRequestHeaderValue(req, tt.key)

			for key, val := range tt.expects {
				ret := getRequestHeaderValue(req, key)
				if diff := cmp.Diff(ret, val); diff != "" {
					t.Errorf("Unset result mismatch, diff=%s", diff)
				}
			}
		})
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

	for _, tt := range tests {
		header := ghttp.Header{}
		header.Set("Foo", "bar")
		header.Add("Text", "lorem=ipsum")
		header.Add("Text", "dolor=sit")
		resp := http.WrapResponse(&ghttp.Response{Header: header})

		unsetResponseHeaderValue(resp, tt.name)
		ret := getResponseHeaderValue(resp, tt.name)
		if diff := cmp.Diff(ret, &value.String{IsNotSet: true}); diff != "" {
			t.Errorf("Unset value still not empty, diff=%s", diff)
		}
	}
}

func TestUnsetResponseHeaderValueWildcard(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		expects map[string]value.Value
	}{
		{
			name: "unset simple wildcard fields",
			key:  "X-*",
			expects: map[string]value.Value{
				"X-SomeHeader-1": &value.String{IsNotSet: true},
				"X-SomeHeader-2": &value.String{IsNotSet: true},
			},
		},
		{
			name: "subfiled wildcard does not be delete",
			key:  "VARS:VALUE*",
			expects: map[string]value.Value{
				"VARS:VALUE1": &value.String{Value: "foo"},
				"VARS:VALUE2": &value.String{Value: "bar"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := ghttp.Header{}
			header.Set("X-SomeHeader-1", "foo")
			header.Set("X-SomeHeader-2", "bar")
			resp := http.WrapResponse(&ghttp.Response{Header: header})
			setResponseHeaderValue(resp, "VARS:VALUE1", &value.String{Value: "foo"})
			setResponseHeaderValue(resp, "VARS:VALUE2", &value.String{Value: "bar"})

			unsetResponseHeaderValue(resp, tt.key)

			for key, val := range tt.expects {
				ret := getResponseHeaderValue(resp, key)
				if diff := cmp.Diff(ret, val); diff != "" {
					t.Errorf("Unset result mismatch, diff=%s", diff)
				}
			}
		})
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
		req := http.WrapRequest(
			httptest.NewRequest(ghttp.MethodGet, "http://localhost", nil),
		)
		req.Header.Add("Cookie", "foo=bar")
		req.Header.Add("Cookie", "cat=meow")
		removeCookieByName(req, tt.name)
		if len(req.Cookies()) != tt.expect {
			t.Errorf("Cookie will not deleted for %s", tt.name)
		}
	}
}
