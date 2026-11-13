package shared

import (
	"net/url"
	"strings"
)

// Param stores one raw query string parameter.
type Param struct {
	Name     string
	Value    string
	HasValue bool // distinguishes "a=" from "a"
}

// QueryStrings preserves parameter encoding, order, and duplicates.
//
// Params is nil when the URL has no "?" at all, and holds one empty Param for a
// bare "?", so joining Params back together reproduces the input byte for byte.
type QueryStrings struct {
	Prefix string
	Params []Param
}

// ParseQuery splits a URL at its first "?" and the query at every "&". Nothing
// is decoded: "+", "%XX", "#" and any later "?" are ordinary bytes.
func ParseQuery(qs string) *QueryStrings {
	prefix, query, found := strings.Cut(qs, "?")
	if !found {
		return &QueryStrings{Prefix: qs}
	}
	ret := &QueryStrings{Prefix: prefix}
	for token := range strings.SplitSeq(query, "&") {
		if name, val, found := strings.Cut(token, "="); found {
			ret.Params = append(ret.Params, Param{Name: name, Value: val, HasValue: true})
		} else {
			ret.Params = append(ret.Params, Param{Name: name})
		}
	}
	return ret
}

// Add appends an escaped name-value pair to the URL as it was parsed.
// Fastly does nothing when the name or the value is empty.
func (q *QueryStrings) Add(name, val string) string {
	raw := q.raw()
	if name == "" || val == "" {
		return raw
	}
	sep := "&"
	if q.Params == nil {
		sep = "?"
	}
	return raw + sep + Escape(name) + "=" + Escape(val)
}

// Set replaces the value of the first parameter whose raw name equals the
// escaped name and drops every later parameter with that name. When nothing
// matches it behaves like Add. Fastly does nothing when the name or the value
// is empty.
func (q *QueryStrings) Set(name, val string) string {
	if name == "" || val == "" {
		return q.raw()
	}
	escaped, replaced := Escape(name), false
	kept := make([]Param, 0, len(q.Params))
	for _, p := range q.Params {
		if p.Name != escaped {
			kept = append(kept, p)
			continue
		}
		if !replaced {
			replaced = true
			kept = append(kept, Param{Name: escaped, Value: Escape(val), HasValue: true})
		}
	}
	if !replaced {
		return q.Add(name, val)
	}
	q.Params = kept
	return q.String()
}

// Clean removes empty parameters and parameters with an empty name.
func (q *QueryStrings) Clean() {
	q.Filter(func(string) bool { return true })
}

// Filter keeps matching parameters. Parameters with an empty name, including
// the empty tokens produced by "&&" or a trailing "&", are always removed.
func (q *QueryStrings) Filter(keep func(name string) bool) {
	var filtered []Param
	for _, v := range q.Params {
		if v.Name == "" || !keep(v.Name) {
			continue
		}
		filtered = append(filtered, v)
	}
	q.Params = filtered
}

// String serializes a rebuilt query the way Fastly does: prefix, "?", the
// parameters joined by "&", then one trailing "?" or "&" removed. That last step
// drops the "?" when no parameters are left ("/p&?a=1" filtered to nothing
// becomes "/p&"), but it also takes one byte off a
// final parameter that ends in "?" ("/p?a=1?" becomes "/p?a=1"), and one "&"
// off a trailing empty parameter kept by Set ("/p?a=1&&&" becomes "/p?a=9&&").
// See https://fiddle.fastly.dev/fiddle/945bb4f9 and
// https://fiddle.fastly.dev/fiddle/e250b311.
func (q *QueryStrings) String() string {
	s := q.join()
	if last := s[len(s)-1]; last == '?' || last == '&' {
		s = s[:len(s)-1]
	}
	return s
}

// raw reproduces the parsed URL byte for byte.
func (q *QueryStrings) raw() string {
	if q.Params == nil {
		return q.Prefix
	}
	return q.join()
}

func (q *QueryStrings) join() string {
	var buf strings.Builder
	buf.WriteString(q.Prefix)
	buf.WriteString("?")
	for i, p := range q.Params {
		if i > 0 {
			buf.WriteString("&")
		}
		buf.WriteString(p.Name)
		if p.HasValue {
			buf.WriteString("=")
			buf.WriteString(p.Value)
		}
	}
	return buf.String()
}

// Escape percent-encodes every byte except ALPHA, DIGIT, "-", ".", "_" and "~",
// with uppercase hex, so a space becomes %20 and "+" becomes %2B. Fastly uses
// this for the names and values that querystring.add and querystring.set write,
// and for the name that querystring.get and querystring.set look up.
func Escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
