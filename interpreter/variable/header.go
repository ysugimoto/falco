package variable

import (
	"net/textproto"
	"strings"

	"github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

func getRequestHeaderValue(r *http.Request, name string) *value.String {
	var key string
	name, key, _ = strings.Cut(name, ":")
	v := r.Header.Get(name)
	if v == "" {
		return &value.String{IsNotSet: !r.IsAssigned(name)}
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
		return &value.String{IsNotSet: !r.IsAssigned(name)}
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
		// Skip when set value is notset
		if s, ok := val.(*value.String); ok && s.IsNotSet {
			return
		}

		// Fastly truncates header values at newlines.
		sVal, _, _ := strings.Cut(val.String(), "\n")
		r.Header.Set(name, sVal)
		r.Assign(name)
		return
	}

	if strings.EqualFold(name, "cookie") {
		c := http.CreateCookie(key, val.String())
		r.AddCookie(c)
		return
	}

	// Handle setting RFC-8941 dictionary value
	r.Header.Set(name, setField(r.Header.Get(name), key, val, ","))
	r.Assign(name)
}

func setResponseHeaderValue(r *http.Response, name string, val value.Value) {
	name, key, found := strings.Cut(name, ":")
	if !found {
		// Skip when set value is notset
		if s, ok := val.(*value.String); ok && s.IsNotSet {
			return
		}

		// Fastly truncates header values at newlines.
		sVal, _, _ := strings.Cut(val.String(), "\n")
		r.Header.Set(name, sVal)
		r.Assign(name)
		return
	}

	// Handle setting RFC-8941 dictionary value
	r.Header.Set(name, setField(r.Header.Get(name), key, val, ","))
	r.Assign(name)
}

func unsetRequestHeaderValue(r *http.Request, name string) {
	// If unset header name ends with "*", remove all matched headers
	if strings.HasSuffix(name, "*") {
		// Note that the wildcard does not work for header subfield
		// ref: https://fiddle.fastly.dev/fiddle/288403c5
		name = strings.TrimSuffix(name, "*")
		for key := range r.Header {
			if strings.HasPrefix(key, name) {
				r.Header.Del(key)
			}
		}
		return
	}

	name, key, found := strings.Cut(name, ":")
	if !found {
		r.Header.Del(name)
		r.Unassign(name)
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
		r.Unassign(name)
		return
	}
	r.Header.Set(name, t)
	r.Unassign(name)
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
	// If unset header name ends with "*", remove all matched headers
	if strings.HasSuffix(name, "*") {
		// Note that the wildcard does not work for header subfield
		// ref: https://fiddle.fastly.dev/fiddle/288403c5
		name = strings.TrimSuffix(name, "*")
		for key := range r.Header {
			if strings.HasPrefix(key, name) {
				r.Header.Del(key)
			}
		}
		return
	}

	name, key, found := strings.Cut(name, ":")
	if !found {
		r.Header.Del(name)
		r.Unassign(name)
		return
	}

	t := unsetField(r.Header.Get(name), key, ",")
	if t == "" {
		r.Header.Del(name)
		r.Unassign(name)
		return
	}
	r.Header.Set(name, t)
	r.Unassign(name)
}
