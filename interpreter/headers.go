package interpreter

import (
	"net/http"
	"net/textproto"
	"strings"

	"github.com/ysugimoto/falco/interpreter/value"
)

// Integreated interface type in order to accept *value.String or *value.LenientString
type HttpHeaderItemType interface {
	String() string
	Copy() value.Value
}

// Atomic struct for header value representation
type HttpHeaderItem struct {
	Key   *value.LenientString
	Value *value.LenientString
}

type HttpHeader map[string][][]HttpHeaderItem

// Implement same methods of Golang http.Header struct but arguments are different
func (h HttpHeader) Set(key string, val HttpHeaderItemType) {
	if pos := strings.Index(key, ":"); pos != -1 {
		h.SetObject(key[:pos], key[pos+1:], val)
		return
	}

	h[textproto.CanonicalMIMEHeaderKey(key)] = [][]HttpHeaderItem{
		{
			HttpHeaderItem{
				Key:   copyToLenientString(val),
				Value: nil,
			},
		},
	}
}

func (h HttpHeader) SetObject(name, key string, val HttpHeaderItemType) {
	v, ok := h[textproto.CanonicalMIMEHeaderKey(name)]
	if !ok {
		h[textproto.CanonicalMIMEHeaderKey(name)] = [][]HttpHeaderItem{
			{
				HttpHeaderItem{
					Key: &value.LenientString{
						Values: []value.Value{
							&value.String{Value: key},
						},
					},
					Value: copyToLenientString(val),
				},
			},
		}
		return
	}

	v[0] = append(v[0], HttpHeaderItem{
		Key: &value.LenientString{
			Values: []value.Value{
				&value.String{Value: key},
			},
		},
		Value: copyToLenientString(val),
	})

}

func (h HttpHeader) Add(key string, val HttpHeaderItemType) {
	v, ok := h[textproto.CanonicalMIMEHeaderKey(key)]
	if !ok {
		h.Set(key, val)
		return
	}
	v = append(v, []HttpHeaderItem{
		{
			Key:   copyToLenientString(val),
			Value: nil,
		},
	})
}

// Get header fields value - always returns ambiguous STRING
func (h HttpHeader) Get(key string) *value.LenientString {
	if pos := strings.Index(key, ":"); pos != -1 {
		return h.GetObject(key[:pos], key[pos+1:])
	}
	hv, ok := h[textproto.CanonicalMIMEHeaderKey(key)]
	if !ok {
		return &value.LenientString{IsNotSet: true}
	}
	if len(hv) == 0 {
		return &value.LenientString{IsNotSet: true}
	}

	// Merge ambiguous strings
	var merged []value.Value
	for _, v := range hv[0] {
		if !v.Key.IsNotSet {
			cpk := v.Key.Copy().(*value.LenientString)
			merged = append(merged, cpk.Values...)
		}
		if v.Value == nil {
			continue
		}
		if !v.Value.IsNotSet {
			if v.Value.StrictString() != "" {
				merged = append(merged, &value.String{Value: "="})
			}
			cpv := v.Value.Copy().(*value.LenientString)
			merged = append(merged, cpv.Values...)
		}
	}

	if len(merged) == 0 {
		return &value.LenientString{IsNotSet: true}
	}
	return &value.LenientString{Values: merged}
}

// Get header fields value for key - always returns ambiguous STRING
func (h HttpHeader) GetObject(name, key string) *value.LenientString {
	hv, ok := h[textproto.CanonicalMIMEHeaderKey(name)]
	if !ok {
		return &value.LenientString{IsNotSet: true}
	}
	if len(hv) == 0 {
		return &value.LenientString{IsNotSet: true}
	}
	for _, v := range hv[0] {
		if v.Key.String() != key {
			continue
		}
		return v.Value.Copy().(*value.LenientString)
	}
	return &value.LenientString{IsNotSet: true}
}

func (h HttpHeader) Del(key string) {
	if pos := strings.Index(key, ":"); pos != -1 {
		h.DelObject(key[:pos], key[pos+1:])
		return
	}
	if _, ok := h[textproto.CanonicalMIMEHeaderKey(key)]; !ok {
		return
	}
	delete(h, textproto.CanonicalMIMEHeaderKey(key))
}

func (h HttpHeader) DelObject(name, key string) {
	hv, ok := h[textproto.CanonicalMIMEHeaderKey(name)]
	if !ok || len(hv) == 0 {
		return
	}

	var filtered []HttpHeaderItem
	for _, v := range hv[0] {
		if v.Key.String() == key {
			continue
		}
		filtered = append(filtered, v)
	}
	hv[0] = filtered
}

// Utility function - create struct from Golang http.Header
func FromGoHttpHeader(h http.Header) HttpHeader {
	v := HttpHeader{}
	for key, val := range h {
		values := make([][]HttpHeaderItem, len(val))
		for i := range val {
			hv := []HttpHeaderItem{}
			obj := strings.Split(val[i], ",")
			for _, vv := range obj {
				if pos := strings.Index(vv, "="); pos != -1 {
					hv = append(hv, HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: strings.TrimSpace(vv[:pos])},
							},
						},
						Value: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: strings.TrimSpace(vv[pos+1:])},
							},
						},
					})
					continue
				}
				hv = append(hv, HttpHeaderItem{
					Key: &value.LenientString{
						Values: []value.Value{
							&value.String{Value: vv},
						},
					},
					Value: nil,
				})
			}
			values[i] = hv
		}
		v[textproto.CanonicalMIMEHeaderKey(key)] = values
	}
	return v
}

// Utility function - convert to Golang http.Header
func ToGoHttpHeader(h HttpHeader) http.Header {
	v := http.Header{}
	for key, val := range h {
		for i := range val {
			var ret []string
			for _, hv := range val[i] {
				if hv.Key.StrictString() == "" {
					continue
				}
				line := hv.Key.String()
				if hv.Value != nil {
					if hv.Value.StrictString() != "" {
						line += "=" + hv.Value.String()
					}
				}
				ret = append(ret, line)
			}
			if r := strings.Join(ret, ","); r != "" {
				v.Add(key, r)
			}
		}
	}
	return v
}

// Check header key or value is implicitly empty.
// On LenientString, NotSet value should be ignored so need type assertion
func isImplicitEmptyString(v HttpHeaderItemType) bool {
	if ls, ok := v.(*value.LenientString); ok {
		return ls.StrictString() == ""
	}
	return v.String() == ""
}

// expliciy copy value as *value.LenientString
func copyToLenientString(v HttpHeaderItemType) *value.LenientString {
	switch t := v.(type) {
	case *value.String:
		ls := &value.LenientString{
			IsNotSet: t.IsNotSet,
		}
		if t.Value != "" {
			ls.Values = append(ls.Values, &value.String{Value: t.Value})
		}
		return ls
	case *value.IP:
		ls := &value.LenientString{
			IsNotSet: t.IsNotSet,
		}
		if t.Value != nil {
			ls.Values = append(ls.Values, &value.String{Value: t.Value.String()})
		}
		return ls
	case *value.LenientString:
		return t.Copy().(*value.LenientString)
	default:
		return &value.LenientString{
			Values: []value.Value{t.Copy()},
		}
	}
}
