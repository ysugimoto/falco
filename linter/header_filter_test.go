package linter

import (
	"testing"
)

func TestHeaderFilterBug(t *testing.T) {
	t.Run("header.filter with multiple string args", func(t *testing.T) {
		input := `
sub vcl_recv {
  #FASTLY RECV
  header.filter(req, "X-Bad1", "X-Bad2");
}
`
		assertNoError(t, input)
	})

	t.Run("header.filter with single string arg", func(t *testing.T) {
		input := `
sub vcl_recv {
  #FASTLY RECV
  header.filter(req, "X-Bad1");
}
`
		assertNoError(t, input)
	})

	t.Run("header.filter_except with multiple string args", func(t *testing.T) {
		input := `
sub vcl_recv {
  #FASTLY RECV
  header.filter_except(req, "Authorization", "Content-Type");
}
`
		assertNoError(t, input)
	})

	t.Run("header.filter with no args should error not panic", func(t *testing.T) {
		input := `
sub vcl_recv {
  #FASTLY RECV
  header.filter();
}
`
		assertError(t, input)
	})

	t.Run("header.filter with only ID arg should error", func(t *testing.T) {
		input := `
sub vcl_recv {
  #FASTLY RECV
  header.filter(req);
}
`
		assertError(t, input)
	})

	t.Run("header.filter_except with no args should error not panic", func(t *testing.T) {
		input := `
sub vcl_recv {
  #FASTLY RECV
  header.filter_except();
}
`
		assertError(t, input)
	})

	t.Run("header.filter with wrong type in variadic args should error", func(t *testing.T) {
		input := `
sub vcl_recv {
  #FASTLY RECV
  header.filter(req, "Authorization", 10);
}
`
		assertError(t, input)
	})

	t.Run("early_hints with variadic string args", func(t *testing.T) {
		input := `
sub vcl_recv {
  #FASTLY RECV
  early_hints("Link", "/style.css", "/script.js");
}
`
		assertNoError(t, input)
	})
}
