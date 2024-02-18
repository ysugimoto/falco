package http

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
		expect := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
				},
			},
			"Content-Type": [][]HeaderItem{
				{
					HeaderItem{
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
		expect := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
				},
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "baz"},
							},
						},
						Value: nil,
					},
				},
			},
			"Content-Type": [][]HeaderItem{
				{
					HeaderItem{
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
		expect := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
					HeaderItem{
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
			"Content-Type": [][]HeaderItem{
				{
					HeaderItem{
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

	t.Run("Cookie header", func(t *testing.T) {
		gh := http.Header{}
		gh.Add("Cookie", "foo=bar; dog=bark")

		hv := FromGoHttpHeader(gh)
		expect := Header{
			"Cookie": [][]HeaderItem{
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "foo"},
							},
						},
						Value: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
					},
					HeaderItem{
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
		}
		if diff := cmp.Diff(expect, hv); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Set-Cookie header", func(t *testing.T) {
		gh := http.Header{}
		gh.Add("Set-Cookie", "session_key=foobar; domain=localhost; path=/; expires=Sat, 25 Jan 2025 19:21:28 GMT; HttpOnly; SameSite=Lax")

		hv := FromGoHttpHeader(gh)
		expect := Header{
			"Set-Cookie": [][]HeaderItem{
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "session_key"},
							},
						},
						Value: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "foobar; domain=localhost; path=/; expires=Sat, 25 Jan 2025 19:21:28 GMT; HttpOnly; SameSite=Lax"},
							},
						},
					},
				},
			},
		}
		if diff := cmp.Diff(expect, hv); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})
}

func TestToGoHttpHeader(t *testing.T) {
	t.Run("Typical Go HTTP Header", func(t *testing.T) {
		h := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
				},
			},
			"Content-Type": [][]HeaderItem{
				{
					HeaderItem{
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
			"X-Bar": [][]HeaderItem{
				{
					HeaderItem{
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
		h := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
				},
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "baz"},
							},
						},
						Value: nil,
					},
				},
			},
			"Content-Type": [][]HeaderItem{
				{
					HeaderItem{
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
		h := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
						Value: nil,
					},
					HeaderItem{
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
			"Content-Type": [][]HeaderItem{
				{
					HeaderItem{
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
		h := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
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
		h := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
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

	t.Run("Cookie header", func(t *testing.T) {
		h := Header{
			"Cookie": [][]HeaderItem{
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "foo"},
							},
						},
						Value: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar"},
							},
						},
					},
					HeaderItem{
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
		}
		gh := ToGoHttpHeader(h)
		expect := http.Header{
			"Cookie": []string{"foo=bar; dog=bark"},
		}
		if diff := cmp.Diff(expect, gh); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Set-Cookie header", func(t *testing.T) {
		h := Header{
			"Set-Cookie": [][]HeaderItem{
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "foo"},
							},
						},
						Value: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bar; domain=localhost; path=/; expires=Sat, 25 Jan 2025 19:21:28 GMT; HttpOnly; SameSite=Lax"},
							},
						},
					},
				},
				{
					HeaderItem{
						Key: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "dog"},
							},
						},
						Value: &value.LenientString{
							Values: []value.Value{
								&value.String{Value: "bark; domain=localhost; path=/; expires=Sat, 25 Jan 2025 19:21:28 GMT; HttpOnly; SameSite=Lax"},
							},
						},
					},
				},
			},
		}
		gh := ToGoHttpHeader(h)
		expect := http.Header{
			"Set-Cookie": []string{
				"foo=bar; domain=localhost; path=/; expires=Sat, 25 Jan 2025 19:21:28 GMT; HttpOnly; SameSite=Lax",
				"dog=bark; domain=localhost; path=/; expires=Sat, 25 Jan 2025 19:21:28 GMT; HttpOnly; SameSite=Lax",
			},
		}
		if diff := cmp.Diff(expect, gh); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})
}

func TestHeaderSet(t *testing.T) {
	t.Run("Usual set", func(t *testing.T) {
		h := Header{}
		h.Set("x-foo", &value.String{Value: "bar"})

		expect := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
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
		h := Header{}
		h.Set("x-foo", &value.LenientString{
			Values: []value.Value{
				&value.String{Value: "bar"},
			},
		})

		expect := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
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
		h := Header{}
		h.Set("x-foo:bar", &value.String{Value: "baz"})

		expect := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
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
		h := Header{}
		h.Set("x-foo:bar", &value.LenientString{
			Values: []value.Value{
				&value.String{Value: "baz"},
			},
		})

		expect := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
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
		h := Header{}
		h.Set("x-foo", &value.LenientString{
			Values: []value.Value{
				&value.String{IsNotSet: true},
			},
		})

		expect := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
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

func TestHeaderGet(t *testing.T) {
	t.Run("Usual get", func(t *testing.T) {
		h := Header{}
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
		h := Header{}
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
		h := Header{}
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
		h := Header{}
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
		h := Header{}
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
		h := Header{}
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

func TestHeaderDel(t *testing.T) {
	t.Run("Usual delete", func(t *testing.T) {
		h := Header{}
		h.Set("x-foo", &value.String{Value: "baz"})

		expect := Header{}
		h.Del("X-Foo")
		if diff := cmp.Diff(expect, h); diff != "" {
			t.Errorf("header mismatch, diff=%s", diff)
		}
	})

	t.Run("Delete for undefined key", func(t *testing.T) {
		h := Header{}
		h.Set("x-foo", &value.String{Value: "baz"})

		expect := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
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
		h := Header{}
		h.Set("x-foo", &value.String{Value: "baz"})
		h.Set("x-foo:bar", &value.String{Value: "baz"})

		expect := Header{
			"X-Foo": [][]HeaderItem{
				{
					HeaderItem{
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
