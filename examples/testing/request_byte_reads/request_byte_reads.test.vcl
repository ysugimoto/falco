// req.body_bytes_read reads the request body in the deliver and log scopes.
// net/http guarantees a server request's Body is always non-nil
// (https://pkg.go.dev/net/http#Request.Body), so the tester synthesizes its mock
// request with an http.NoBody body to match. The read then returns a byte count
// instead of dereferencing a nil body; the mock GET request has no body, so the
// count is 0.

// @scope: deliver
sub test_deliver_request_byte_reads {
  testing.call_subroutine("vcl_deliver");
  assert.equal(req.body_bytes_read, 0);
}

// @scope: log
sub test_log_request_byte_reads {
  testing.call_subroutine("vcl_log");
  assert.equal(req.body_bytes_read, 0);
}
