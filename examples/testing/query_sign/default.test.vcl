sub test_vcl_recv {
  testing.call_subroutine("vcl_recv");
  assert.equal(req.url, "/test?foo=bar");
}

sub test_empty_query_sign {
  set req.url = "/test?";
  assert.equal(req.url, "/test?");
}
