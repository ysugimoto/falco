package interpreter

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ysugimoto/falco/interpreter/value"
)

func TestFromGoHttpHeader(t *testing.T) {
	t.Run("Typical Go HTTP Header", func(t *testing.T) {
		gh := http.Header{}
		gh.Add("X-Foo", "bar")
		gh.Add("Content-Type", "text/plain")

		hv := FromGoHttpHeader(gh)
		expect := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
				},
			},
			"Content-Type": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "text/plain"},
							},
						},
						Value: nil,
					},
				},
			},
		}
		if diff := cmp.Diff(expect, hv); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Multiple Headers", func(t *testing.T) {
		gh := http.Header{}
		gh.Add("Content-Type", "text/plain")
		gh.Add("X-Foo", "bar")
		gh.Add("X-Foo", "baz")

		hv := FromGoHttpHeader(gh)
		expect := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
				},
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "baz"},
							},
						},
						Value: nil,
					},
				},
			},
			"Content-Type": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "text/plain"},
							},
						},
						Value: nil,
					},
				},
			},
		}
		if diff := cmp.Diff(expect, hv); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Includes objective values", func(t *testing.T) {
		gh := http.Header{}
		gh.Add("Content-Type", "text/plain")
		gh.Add("X-Foo", "bar,dog=bark")

		hv := FromGoHttpHeader(gh)
		expect := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "dog"},
							},
						},
						Value: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bark"},
							},
						},
					},
				},
			},
			"Content-Type": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "text/plain"},
							},
						},
						Value: nil,
					},
				},
			},
		}
		if diff := cmp.Diff(expect, hv); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})
}

func TestToGoHeader(t *testing.T) {
	t.Run("Typical Go HTTP Header", func(t *testing.T) {
		h := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
				},
			},
			"Content-Type": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "text/plain"},
							},
						},
						Value: nil,
					},
				},
			},
			// should be skipped because empty header value
			"X-Bar": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key:   &value.LenientString{IsNotSet: true},
						Value: nil,
					},
				},
			},
		}
		gh := ToGoHttpHeader(h)
		expect := http.Header{
			"X-Foo":        []string{"bar"},
			"Content-Type": []string{"text/plain"},
		}
		if diff := cmp.Diff(expect, gh); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Multiple Headers", func(t *testing.T) {
		h := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
				},
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "baz"},
							},
						},
						Value: nil,
					},
				},
			},
			"Content-Type": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "text/plain"},
							},
						},
						Value: nil,
					},
				},
			},
		}
		gh := ToGoHttpHeader(h)
		expect := http.Header{
			"X-Foo":        []string{"bar", "baz"},
			"Content-Type": []string{"text/plain"},
		}
		if diff := cmp.Diff(expect, gh); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Includes objective values", func(t *testing.T) {
		h := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "dog"},
							},
						},
						Value: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bark"},
							},
						},
					},
				},
			},
			"Content-Type": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "text/plain"},
							},
						},
						Value: nil,
					},
				},
			},
		}
		gh := ToGoHttpHeader(h)
		expect := http.Header{
			"X-Foo":        []string{"bar,dog=bark"},
			"Content-Type": []string{"text/plain"},
		}
		if diff := cmp.Diff(expect, gh); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Includes notset value", func(t *testing.T) {
		h := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							IsNotSet: true,
						},
						Value: nil,
					},
				},
			},
		}
		gh := ToGoHttpHeader(h)
		expect := http.Header{}
		if diff := cmp.Diff(expect, gh); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Includes notset value in combinated expression", func(t *testing.T) {
		h := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.Boolean{Value: true},
								&value.String{IsNotSet: true},
							},
						},
						Value: nil,
					},
				},
			},
		}
		gh := ToGoHttpHeader(h)
		expect := http.Header{
			"X-Foo": []string{"1(null)"},
		}
		if diff := cmp.Diff(expect, gh); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})
}

func TestHttpHeaderSet(t *testing.T) {
	t.Run("Usual set", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo", &value.String{Value: "bar"})

		expect := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
				},
			},
		}
		if diff := cmp.Diff(expect, h); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})
	t.Run("Usual set (lenient)", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo", &value.LenientString{
			Values: []value.Value{
				&value.String{Value: "bar"},
			},
		})

		expect := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
				},
			},
		}
		if diff := cmp.Diff(expect, h); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Objective set", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo:bar", &value.String{Value: "baz"})

		expect := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "baz"},
							},
						},
					},
				},
			},
		}
		if diff := cmp.Diff(expect, h); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Objective set (lenient)", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo:bar", &value.LenientString{
			Values: []value.Value{
				&value.String{Value: "baz"},
			},
		})

		expect := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "baz"},
							},
						},
					},
				},
			},
		}
		if diff := cmp.Diff(expect, h); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Includes notset string", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo", &value.LenientString{
			Values: []value.Value{
				&value.String{IsNotSet: true},
			},
		})

		expect := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{IsNotSet: true},
							},
						},
						Value: nil,
					},
				},
			},
		}
		if diff := cmp.Diff(expect, h); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})
}

func TestHttpHeaderGet(t *testing.T) {
	t.Run("Usual get", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo", &value.String{Value: "bar"})

		expect := &value.LenientString{
			Values: []value.Value{
				&value.String{Value: "bar"},
			},
		}
		v := h.Get("X-Foo")
		if diff := cmp.Diff(expect, v); diff != "" {
			t.Errorf("value mismatch, diff=%s", diff)
		}
	})
	t.Run("Usual get(notset)", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo", &value.String{IsNotSet: true})

		expect := &value.LenientString{
			IsNotSet: true,
		}
		v := h.Get("X-Foo")
		if diff := cmp.Diff(expect, v); diff != "" {
			t.Errorf("value mismatch, diff=%s", diff)
		}
	})
	t.Run("Get for undefined field", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo", &value.String{Value: "bar"})

		expect := &value.LenientString{
			IsNotSet: true,
		}
		v := h.Get("X-Baz")
		if diff := cmp.Diff(expect, v); diff != "" {
			t.Errorf("value mismatch, diff=%s", diff)
		}
	})

	t.Run("Objective get", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo:bar", &value.String{Value: "baz"})

		expect := &value.LenientString{
			Values: []value.Value{
				&value.String{Value: "baz"},
			},
		}
		v := h.Get("X-Foo:bar")
		if diff := cmp.Diff(expect, v); diff != "" {
			t.Errorf("value mismatch, diff=%s", diff)
		}
	})
	t.Run("Get for undefined object field", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo", &value.String{Value: "bar"})

		expect := &value.LenientString{
			IsNotSet: true,
		}
		v := h.Get("X-Foo:Baz")
		if diff := cmp.Diff(expect, v); diff != "" {
			t.Errorf("value mismatch, diff=%s", diff)
		}
	})

	t.Run("Object get", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo:bar", &value.String{Value: "baz"})

		expect := &value.LenientString{
			Values: []value.Value{
				&value.String{Value: "bar"},
				&value.String{Value: "="},
				&value.String{Value: "baz"},
			},
		}
		v := h.Get("X-Foo")
		if diff := cmp.Diff(expect, v); diff != "" {
			t.Errorf("value mismatch, diff=%s", diff)
		}
	})
}

func TestHttpHeaderDel(t *testing.T) {
	t.Run("Usual delete", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo", &value.String{Value: "baz"})

		expect := HttpHeader{}
		h.Del("X-Foo")
		if diff := cmp.Diff(expect, h); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Delete for undefined key", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo", &value.String{Value: "baz"})

		expect := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "baz"},
							},
						},
						Value: nil,
					},
				},
			},
		}
		h.Del("X-Bar")
		if diff := cmp.Diff(expect, h); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Objective delete", func(t *testing.T) {
		h := HttpHeader{}
		h.Set("x-foo", &value.String{Value: "baz"})
		h.Set("x-foo:bar", &value.String{Value: "baz"})

		expect := HttpHeader{
			"X-Foo": [][]HttpHeaderItem{
				{
					HttpHeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "baz"},
							},
						},
						Value: nil,
					},
				},
			},
		}
		h.Del("X-foo:bar")
		if diff := cmp.Diff(expect, h); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})
}
