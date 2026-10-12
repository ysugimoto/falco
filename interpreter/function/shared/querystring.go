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
type QueryStrings struct {
	Prefix string
	Params []Param
}

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

// Add appends an escaped, non-empty name-value pair.
func (q *QueryStrings) Add(name, val string) {
	if name == "" || val == "" {
		return
	}
	q.Params = append(q.Params, Param{Name: Escape(name), Value: Escape(val), HasValue: true})
}

// Set replaces or appends a non-empty pair while removing later duplicates.
func (q *QueryStrings) Set(name, val string) {
	if name == "" || val == "" {
		return
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
	q.Params = kept
	if !replaced {
		q.Params = append(q.Params, Param{Name: escaped, Value: Escape(val), HasValue: true})
	}
}

// Clean removes parameters with empty names.
func (q *QueryStrings) Clean() {
	var cleaned []Param
	for _, v := range q.Params {
		if v.Name == "" {
			continue
		}
		cleaned = append(cleaned, v)
	}
	q.Params = cleaned
}

// Filter keeps matching parameters with non-empty raw names.
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

func (q *QueryStrings) String() string {
	if len(q.Params) == 0 {
		return q.Prefix
	}
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

// Escape encodes a query component with spaces represented as %20.
func Escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
