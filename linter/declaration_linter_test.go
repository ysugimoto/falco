package linter

import (
	"fmt"
	"testing"
)

func TestLintAclDeclaration(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
acl example {
  !"192.168.0.1"/32;
}`
		assertNoError(t, input)
	})

	t.Run("invalid acl name", func(t *testing.T) {
		input := `
acl invalid-acl-name {
  !"192.168.0.1"/32;
}`
		assertError(t, input)
	})

	t.Run("duplicated error", func(t *testing.T) {
		input := `
acl example {
  !"192.168.0.1"/32;
}

acl example {
  "192.168.0.2"/32;
}
`
		assertError(t, input)
	})
}

func TestLintBackendDeclaration(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
backend foo {
  .host = "example.com";
  .host_header = "example.com";
  .always_use_host_header = true;
  .keepalive_time = 30s;
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .first_byte_timeout = 20s;
  .max_connections = 500;
  .between_bytes_timeout = 20s;
  .share_key = "xei5lohleex3Joh5ie5uy7du";
  .ssl = true;
  .ssl_sni_hostname = "httpbin.org";
  .ssl_cert_hostname = "httpbin.org";
  .ssl_check_cert = always;
  .min_tls_version = "1.2";
  .max_tls_version = "1.2";
  .prefer_ipv6 = true;
  .probe = {
    .dummy = false;
    .initial = 5;
    .request = "GET / HTTP/1.1";
    .threshold = 1;
    .timeout = 2s;
    .window = 4;
  }
}`
		assertNoError(t, input)
	})

	t.Run("invalid backend name", func(t *testing.T) {
		input := `
backend foo-bar {
  .host = "example.com";
}`
		assertError(t, input)
	})

	t.Run("invalid type", func(t *testing.T) {
		input := `
backend foo {
  .host = 1s;
}`
		assertError(t, input)
	})

	t.Run("invalid share_key", func(t *testing.T) {
		input := `
backend foo {
  .share_key = "example.com";
}`
		assertError(t, input)
	})

	t.Run("duplicate backend", func(t *testing.T) {
		input := `
backend foo {
  .host = "example.com";
}

backend foo {
  .host = "example.com";
}`
		assertError(t, input)
	})

	t.Run("probe must be an object", func(t *testing.T) {
		input := `
backend foo {
  .host = "example.com";
  .probe = "probe";
}
`
		assertError(t, input)
	})

	t.Run("Probe is configured correctly", func(t *testing.T) {
		input := `
backend foo {
  .host = "example.com";

  .probe = {
    .request = "GET / HTTP/1.1";
	.threshold = 1;
	.initial = 5;
  }
}`
		assertNoError(t, input)
	})

	t.Run("Probe is configured in such a way that the backend will start as unhealthy", func(t *testing.T) {
		input := `
backend foo {
  .host = "example.com";

  .probe = {
    .request = "GET / HTTP/1.1";
	.threshold = 5;
	.initial = 1;
  }
}`
		assertError(t, input)
	})
}

func TestLintTableDeclaration(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
table example {
	"foo": "bar",
}`
		assertNoError(t, input)
	})

	t.Run("invalid table name", func(t *testing.T) {
		input := `
table example-table {
	"foo": "bar",
}`
		assertError(t, input)
	})

	t.Run("invalid table value type", func(t *testing.T) {
		input := `
table example INTEGER {
	"foo": 1s,
}`
		assertError(t, input)
	})

	t.Run("dulicated definition", func(t *testing.T) {
		input := `
table example INTEGER {
	"foo": 10,
}
table example  {
	"foo": "bar",
}`
		assertError(t, input)
	})
}

func TestLintDirectorDeclaration(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar client {
	.quorum  = 50%;
	{ .backend = foo; .weight = 1; }
}

director fiz chash {
	{ .backend = foo; .id = "foo"; }
}`
		assertNoError(t, input)
	})

	t.Run("invalid director name", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar-baz client {
	.quorum  = 50%;
	{ .backend = foo; .weight = 1; }
}`
		assertError(t, input)
	})

	t.Run("unexpected director property", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar fallback {
	{ .backend = foo; .weight = 1; }
}`
		assertError(t, input)
	})

	t.Run("invalid director type", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar testing {
	{ .backend = foo; }
}`
		assertError(t, input)
	})

	t.Run("duplicate director declared", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar fallback {
	{ .backend = foo; }
}

director bar fallback {
	{ .backend = foo; }
}`
		assertError(t, input)
	})

	t.Run("required backend property is not declared", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar client {
	{ .backend = foo; }
}`

		assertError(t, input)
	})

	t.Run("backend is not declared in director", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar client {
	.quorum = 50%;
}`

		assertError(t, input)
	})

	t.Run("undefined backend is specified", func(t *testing.T) {
		input := `
backend foo {
	.host = "example.com";
}

director bar client {
	.quorum = 50%;
	{ .backend = baz; .weight = 1; }
}`

		assertError(t, input)
	})
}

func TestLintSubroutineDeclaration(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
sub example {
	set req.http.Host = "example.com";
}`
		assertNoError(t, input)
	})

	t.Run("pass with Fastly reserved subroutine boilerplate comment", func(t *testing.T) {
		input := `
sub vcl_recv {
	#FASTLY recv
	set req.http.Host = "example.com";
}`
		assertNoError(t, input)

		input = `
sub vcl_log {
	# FASTLY log
}`
		assertError(t, input)
	})

	t.Run("invalid subroutine name", func(t *testing.T) {
		input := `
sub vcl-recv {
	set req.http.Host = "example.com";
}`
		assertError(t, input)
	})

	t.Run("duplicate subroutine declared", func(t *testing.T) {
		input := `
sub foo {
	set req.http.Host = "example.com";
}

sub foo {
	set req.http.Host = "httpbin.org";
}`
		assertError(t, input)
	})

	t.Run("Fastly reserved subroutine needs boilerplate comment", func(t *testing.T) {
		input := `
sub vcl_recv {
	set req.http.Host = "example.com";
}`
		assertError(t, input)
	})

	t.Run("Fastly reserved subroutine cannot have a return type", func(t *testing.T) {
		input := `
sub vcl_recv BOOL {
	set req.http.Host = "example.com";
	return true;
}`
		assertError(t, input)
	})

	t.Run("Subroutines can be reused in multiple vcl state functions", func(t *testing.T) {
		input := `
//@recv, log
sub example {
	set req.http.Host = "example.com";
}

sub vcl_log {
    #FASTLY log
	call example;
}

sub vcl_recv {
#FASTLY recv
call example;
}
`
		assertNoError(t, input)
	})

	t.Run("subroutine with typed parameters and return type", func(t *testing.T) {
		input := `
sub concat_fetch(STRING var.left, STRING var.right) STRING {
  declare local var.both STRING = var.left + var.right;
  return var.both;
}

sub vcl_recv {
  log concat_fetch("Hello, ", "world!");
#FASTLY recv
}
`
		assertNoError(t, input)
	})
}

func TestLintPenaltyboxDeclaration(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
penaltybox ip_pb {}
`
		assertNoError(t, input)
	})

	t.Run("pass with comments", func(t *testing.T) {
		input := `
penaltybox ip_pb {
	// This is a comment
}
`
		assertNoError(t, input)
	})

	t.Run("invalid penaltybox name", func(t *testing.T) {
		input := `
penaltybox vcl-recv {}
	`
		assertError(t, input)
	})

	t.Run("duplicate penaltybox declared", func(t *testing.T) {
		input := `
penaltybox ip_pb {}
penaltybox ip_pb {}
	`
		assertError(t, input)
	})

	t.Run("penaltybox block is not empty", func(t *testing.T) {
		input := `
penaltybox ip_pb {
	set var.bar = "baz";
}
`
		assertError(t, input)
	})

	t.Run("penaltybox variable should be pass if it is defined", func(t *testing.T) {
		input := `
penaltybox ip_pb {}
ratecounter counter_60 {}

sub test_sub{
	declare local var.ratelimit_exceeded BOOL;
	set var.ratelimit_exceeded = ratelimit.check_rate(
		digest.hash_sha256("123"),
		counter_60,
		1,
		60,
		135,
		ip_pb,
		2m);
}
`
		assertNoError(t, input)
	})

	t.Run("penaltybox variable should be defined", func(t *testing.T) {
		input := `
ratecounter counter_60 {}

sub test_sub{
	declare local var.ratelimit_exceeded BOOL;
	set var.ratelimit_exceeded = ratelimit.check_rate(
		digest.hash_sha256("123"),
		counter_60,
		1,
		60,
		135,
		ip_pb,
		2m);
}
`
		assertError(t, input)
	})
}

func TestLintRatecounterDeclaration(t *testing.T) {
	t.Run("pass", func(t *testing.T) {
		input := `
ratecounter req_counter {}
`
		assertNoError(t, input)
	})

	t.Run("pass with comments", func(t *testing.T) {
		input := `
ratecounter req_counter {
	// This is a comment
}
`
		assertNoError(t, input)
	})

	t.Run("invalid ratecounter name", func(t *testing.T) {
		input := `
ratecounter vcl-recv {}
	`
		assertError(t, input)
	})

	t.Run("duplicate ratecounter declared", func(t *testing.T) {
		input := `
ratecounter req_counter {}
ratecounter req_counter {}
	`
		assertError(t, input)
	})

	t.Run("ratecounter block is not empty", func(t *testing.T) {
		input := `
ratecounter req_counter {
	set var.bar = "baz";
}
`
		assertError(t, input)
	})

	t.Run("ratecounter variable should be pass if it is defined", func(t *testing.T) {
		input := `
penaltybox ip_pb {}
ratecounter counter_60 {}

sub test_sub{
	declare local var.ratelimit_exceeded BOOL;
	set var.ratelimit_exceeded = ratelimit.check_rate(
		digest.hash_sha256("123"),
		counter_60,
		1,
		60,
		135,
		ip_pb,
		2m);
}
`
		assertNoError(t, input)
	})

	t.Run("ratecounter variable should be defined", func(t *testing.T) {
		input := `
penaltybox ip_pb {}

sub test_sub{
	declare local var.ratelimit_exceeded BOOL;
	set var.ratelimit_exceeded = ratelimit.check_rate(
		digest.hash_sha256("123"),
		counter_60,
		1,
		60,
		135,
		ip_pb,
		2m);
}
`
		assertError(t, input)
	})

	t.Run("ratecounter bucket variables should pass if the ratecounter is defined", func(t *testing.T) {
		input := `
ratecounter counter_60 {}

sub test_sub{
	set req.http.X-ERL:tls_bucket_10s = std.itoa(ratecounter.counter_60.bucket.10s);
}
`
		assertNoError(t, input)
	})

	t.Run("ratecounter bucket variables should not pass if the ratecounter is not defined", func(t *testing.T) {
		input := `
ratecounter counter_60 {}

sub test_sub{
	set req.http.X-ERL:tls_rate_10s = std.itoa(ratecounter.counter.bucket.10s);
}
`
		assertError(t, input)
	})

	t.Run("ratecounter bucket variables should exist", func(t *testing.T) {
		input := `
ratecounter counter_60 {}

sub test_sub{
	set req.http.X-ERL:tls_bucket_10s = std.itoa(ratecounter.counter_60.bucket.100s);
}
`
		assertError(t, input)
	})
}

func TestFastlyBoilerPlateMacro(t *testing.T) {
	tests := []struct {
		name    string
		macro   string
		isError bool
	}{
		{
			name:    "Disallow slash comment sign",
			macro:   "//FASTLY RECV",
			isError: true,
		},
		{
			name:    "Disallow double or more comment sign",
			macro:   "###FASTLY RECV",
			isError: true,
		},
		{
			name:    "Disallow lowercase fastly string",
			macro:   "#fastly RECV",
			isError: true,
		},
		{
			name:  "Allow uppercase scope",
			macro: "#FASTLY RECV",
		},
		{
			name:  "Allow lowercase scope",
			macro: "#FASTLY recv",
		},
		{
			name:  "Allow extra comments",
			macro: "#FASTLY RECV foo bar baz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := fmt.Sprintf(`
sub vcl_recv {
%s
set req.http.Foo = "bar";
}`,
				tt.macro,
			)
			if tt.isError {
				assertError(t, input)
			} else {
				assertNoError(t, input)
			}
		})
	}
}
