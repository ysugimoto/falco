package variable

import (
	"fmt"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/ysugimoto/falco/interpreter/value"
)

func getRequestHeaderValue(r *http.Request, name string) *value.String {
	var key string
	name, key, _ = strings.Cut(name, ":")
	v := r.Header.Get(name)
	if v == "" {
		return &value.String{IsNotSet: true}
	}

	if key == "" {
		return &value.String{Value: v}
	}

	// Request header can modify cookie, then we need to retrieve value from Cookie pointer
	if strings.EqualFold(name, "cookie") {
		for _, c := range r.Cookies() {
			if c.Name == key {
				return &value.String{Value: c.Value}
			}
		}
	}

	// Handle reading RFC-8941 dictionary value
	return GetField(v, key, ",")
}

func getResponseHeaderValue(r *http.Response, name string) *value.String {
	var key string
	name, key, _ = strings.Cut(name, ":")
	v := r.Header.Get(name)
	if v == "" {
		return &value.String{IsNotSet: true}
	}

	if key == "" {
		return &value.String{Value: v}
	}

	// Handle reading RFC-8941 dictionary value
	return GetField(v, key, ",")
}

func setRequestHeaderValue(r *http.Request, name string, val value.Value) {
	name, key, found := strings.Cut(name, ":")
	if !found {
		// Fastly truncates header values at newlines.
		sVal, _, _ := strings.Cut(val.String(), "\n")
		r.Header.Set(name, sVal)
		return
	}

	if strings.EqualFold(name, "cookie") {
		hh := http.Header{}
		hh.Add("Cookie", fmt.Sprintf("%s=%s", key, val.String()))
		rr := http.Request{Header: hh}
		c, _ := rr.Cookie(key) // nolint:errcheck
		r.AddCookie(c)
		return
	}

	// Handle setting RFC-8941 dictionary value
	r.Header.Set(name, setField(r.Header.Get(name), key, val, ","))
}

func setResponseHeaderValue(r *http.Response, name string, val value.Value) {
	name, key, found := strings.Cut(name, ":")
	if !found {
		// Fastly truncates header values at newlines.
		sVal, _, _ := strings.Cut(val.String(), "\n")
		r.Header.Set(name, sVal)
		return
	}

	// Handle setting RFC-8941 dictionary value
	r.Header.Set(name, setField(r.Header.Get(name), key, val, ","))
}

func unsetRequestHeaderValue(r *http.Request, name string) {
	name, key, found := strings.Cut(name, ":")
	if !found {
		r.Header.Del(name)
		return
	}

	// Request header can modify cookie, then we need to unset value from Cookie pointer
	if strings.EqualFold(name, "cookie") {
		removeCookieByName(r, key)
		return
	}

	// Handle removing RFC-8941 dictionary value
	t := unsetField(r.Header.Get(name), key, ",")
	if t == "" {
		r.Header.Del(name)
		return
	}
	r.Header.Set(name, t)
}

// removeCookieByName removes a part of Cookie headers that name is matched.
// Go does not have DeleteCookie() method, so we need to modify actual header value.
// This logic refers to readCookies() in net/http package.
func removeCookieByName(r *http.Request, cookieName string) {
	lines := r.Header["Cookie"]
	if len(lines) == 0 {
		return
	}

	var filtered []string
	for _, line := range lines {
		line = textproto.TrimString(line)

		var sub []string
		var part string
		for len(line) > 0 { // continue since we have rest
			part, line, _ = strings.Cut(line, ";")
			trimmedPart := textproto.TrimString(part)
			if trimmedPart == "" {
				continue
			}
			name, _, _ := strings.Cut(trimmedPart, "=")
			name = textproto.TrimString(name)
			if name == cookieName {
				continue
			}
			sub = append(sub, part)
		}

		if len(sub) > 0 {
			filtered = append(filtered, strings.Join(sub, ";"))
		}
	}
	if len(filtered) > 0 {
		r.Header["Cookie"] = filtered
	} else {
		r.Header.Del("Cookie")
	}
}

func unsetResponseHeaderValue(r *http.Response, name string) {
	name, key, found := strings.Cut(name, ":")
	if !found {
		r.Header.Del(name)
		return
	}

	t := unsetField(r.Header.Get(name), key, ",")
	if t == "" {
		r.Header.Del(name)
		return
	}
	r.Header.Set(name, t)
}
