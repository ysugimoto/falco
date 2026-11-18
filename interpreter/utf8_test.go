package interpreter

import (
	"testing"

	"github.com/ysugimoto/falco/v2/interpreter/context"
	"github.com/ysugimoto/falco/v2/interpreter/value"
)

// These tests also check that fastly.error reports what a built-in function recorded.
func TestUnicodeFunctions(t *testing.T) {
	// "bad-utf8\xFF", the shortest way to write ill-formed UTF-8 in VCL.
	const badUtf8 = `digest.base64_decode("YmFkLXV0Zjj/")`

	tests := []struct {
		name       string
		vcl        string
		assertions map[string]value.Value
	}{
		{
			name: "utf8.translate maps every character of set1",
			vcl: `
				set req.http.Plain = "Hello, world!";
				set req.http.Rot13 = utf8.translate(req.http.Plain,
					"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
					"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm");
				set req.http.Folded = utf8.translate("être", "éèê", "e");
				set req.http.Error = fastly.error;`,
			assertions: map[string]value.Value{
				"req.http.Rot13":  &value.String{Value: "Uryyb, jbeyq!"},
				"req.http.Folded": &value.String{Value: "etre"},
				"req.http.Error":  &value.String{Value: ""},
			},
		},
		{
			name: "utf8.translate reports EUTF8 for ill-formed input",
			vcl: `
				set req.http.Translated = utf8.translate(` + badUtf8 + `, "a", "b");
				set req.http.Error = fastly.error;`,
			assertions: map[string]value.Value{
				"req.http.Translated": &value.String{IsNotSet: true},
				"req.http.Error":      &value.String{Value: "EUTF8"},
			},
		},
		{
			name: "utf8.strpad reports EUTF8 for ill-formed input",
			vcl: `
				set req.http.Padded = utf8.strpad(` + badUtf8 + `, 20, "-");
				set req.http.Error = fastly.error;`,
			assertions: map[string]value.Value{
				"req.http.Padded": &value.String{IsNotSet: true},
				"req.http.Error":  &value.String{Value: "EUTF8"},
			},
		},
		{
			name: "utf8.strpad reports EDOM for the smallest INTEGER width",
			vcl: `
				set req.http.Padded = utf8.strpad("abc", -9223372036854775808, "-");
				set req.http.Error = fastly.error;`,
			assertions: map[string]value.Value{
				"req.http.Padded": &value.String{Value: ""},
				"req.http.Error":  &value.String{Value: "EDOM"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vcl := "sub vcl_recv {" + tt.vcl + "\n}"
			assertInterpreter(t, vcl, context.RecvScope, tt.assertions, false)
		})
	}
}
