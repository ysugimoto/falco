// @scope: recv
// @suite: Foo request header should contains "hoge"
sub test_vcl_recv {
  set req.http.Foo = "bar";
  testing.call_subroutine("vcl_recv");

  assert.equal(req.backend, httpbin_org);
  assert.contains(req.http.Foo, "hoge");
}

// @scope: deliver
// @suite: X-Custom-Header response header should contains "hoge"
sub test_vcl_deliver {
  set req.http.Foo = "bar";
  testing.call_subroutine("vcl_deliver");
  assert.contains(resp.http.X-Custom-Header, "hoge");
}


// @scope: recv
// @suite: Checking auth raise an error with 401 status code
sub test_check_auth {
  set req.http.Check-Auth = "1";
  testing.call_subroutine("vcl_recv");

  assert.equal(testing.state, "ERROR");
  assert.equal(testing.inspect("obj.status"), 401);
}
