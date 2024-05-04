package variable

import (
	"fmt"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/ysugimoto/falco/interpreter/value"
)

func getRequestHeaderValue(r *http.Request, name string) *value.String {
	// Header name can contain ":" for object-like value
	if !strings.Contains(name, ":") {
		v := strings.Join(r.Header.Values(name), ", ")
		if v == "" {
			return &value.String{IsNotSet: true}
		}
		return &value.String{Value: v}
	}
	spl := strings.SplitN(name, ":", 2)
	// Request header can modify cookie, then we need to retrieve value from Cookie pointer
	if strings.EqualFold(spl[0], "cookie") {
		for _, c := range r.Cookies() {
			if c.Name == spl[1] {
				return &value.String{Value: c.Value}
			}
		}
	}

	for _, hv := range r.Header.Values(spl[0]) {
		kvs := strings.SplitN(hv, "=", 2)
		if kvs[0] == spl[1] {
			return &value.String{Value: kvs[1]}
		}
	}
	return &value.String{IsNotSet: true}
}

func getResponseHeaderValue(r *http.Response, name string) *value.String {
	// Header name can contain ":" for object-like value
	if !strings.Contains(name, ":") {
		v := strings.Join(r.Header.Values(name), ", ")
		if v == "" {
			return &value.String{IsNotSet: true}
		}
		return &value.String{Value: v}
	}

	spl := strings.SplitN(name, ":", 2)
	for _, hv := range r.Header.Values(spl[0]) {
		kvs := strings.SplitN(hv, "=", 2)
		if kvs[0] == spl[1] {
			return &value.String{Value: kvs[1]}
		}
	}
	return &value.String{IsNotSet: true}
}

func setRequestHeaderValue(r *http.Request, name string, val value.Value) {
	if !strings.Contains(name, ":") {
		r.Header.Set(name, val.String())
		return
	}

	// If name contains ":" like req.http.VARS:xxx, add with key-value format
	// HTTP Request can modify cookie
	spl := strings.SplitN(name, ":", 2)
	if strings.EqualFold(spl[0], "cookie") {
		hh := http.Header{}
		hh.Add("Cookie", fmt.Sprintf("%s=%s", spl[1], val.String()))
		rr := http.Request{Header: hh}
		c, _ := rr.Cookie(spl[1]) // nolint:errcheck
		r.AddCookie(c)
		return
	}
	r.Header.Add(spl[0], fmt.Sprintf("%s=%s", spl[1], val.String()))
}

func setResponseHeaderValue(r *http.Response, name string, val value.Value) {
	if !strings.Contains(name, ":") {
		r.Header.Set(name, val.String())
		return
	}

	// If name contains ":" like req.http.VARS:xxx, add with key-value format
	spl := strings.SplitN(name, ":", 2)
	r.Header.Add(spl[0], fmt.Sprintf("%s=%s", spl[1], val.String()))
}

func unsetRequestHeaderValue(r *http.Request, name string) {
	if !strings.Contains(name, ":") {
		r.Header.Del(name)
		return
	}

	// Header name contains ":" character, then filter value by key
	spl := strings.SplitN(name, ":", 2)
	// Request header can modify cookie, then we need to unset value from Cookie pointer
	if strings.EqualFold(spl[0], "cookie") {
		removeCookieByName(r, spl[1])
		return
	}

	var filtered []string
	for _, hv := range r.Header.Values(spl[0]) {
		kvs := strings.SplitN(hv, "=", 2)
		if kvs[0] == spl[1] {
			continue
		}
		filtered = append(filtered, hv)
	}

	if len(filtered) > 0 {
		r.Header[spl[0]] = filtered
	} else {
		r.Header.Del(name)
	}
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
		for line != "" { // continue since we have rest
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
	if !strings.Contains(name, ":") {
		r.Header.Del(name)
		return
	}

	// Header name contains ":" character, then filter value by key
	spl := strings.SplitN(name, ":", 2)
	var filtered []string
	for _, hv := range r.Header.Values(spl[0]) {
		kvs := strings.SplitN(hv, "=", 2)
		if kvs[0] == spl[1] {
			continue
		}
		filtered = append(filtered, hv)
	}

	if len(filtered) > 0 {
		r.Header[spl[0]] = filtered
	} else {
		r.Header.Del(name)
	}
}
