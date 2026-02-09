// @scope: recv
// @suite: req.protocol injection
sub test_inject_req_protocol {
  testing.inject_variable("req.protocol", "https");
  testing.call_subroutine("vcl_recv");
  
  assert.equal(req.protocol, "https");
}

// @scope: recv
// @suite: default req.protocol
sub test_default_req_protocol {
  testing.call_subroutine("vcl_recv");
  
  // Default protocol is http (no TLS)
  assert.equal(req.protocol, "http");
}
