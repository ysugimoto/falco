// @scope: recv
// @suite: Default host without override
sub test_default_host {
  testing.call_subroutine("vcl_recv");
  // By default, Host header is localhost in testing
  assert.equal(req.http.X-Routed-Host, "localhost");
}

// @scope: recv
// @suite: Override host to example.com
sub test_override_host_example_com {
  // Override the Host header to example.com
  testing.override_host("example.com");
  testing.call_subroutine("vcl_recv");
  
  // Verify the host was overridden
  assert.equal(req.http.X-Routed-Host, "example.com");
  // Verify the backend was selected based on the overridden host
  assert.equal(req.backend, example_com);
}

// @scope: recv
// @suite: Override host to fastly.com
sub test_override_host_fastly_com {
  // Override the Host header to fastly.com
  testing.override_host("fastly.com");
  testing.call_subroutine("vcl_recv");
  
  // Verify the host was overridden
  assert.equal(req.http.X-Routed-Host, "fastly.com");
  // Verify the backend was selected based on the overridden host
  assert.equal(req.backend, fastly_com);
}
