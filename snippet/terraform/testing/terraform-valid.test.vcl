// @scope: recv
// @suite: Backend is set to "F_foo_backend"
sub test_vcl_recv {
  set req.http.Foo = "127.0.0.1";
  testing.call_subroutine("vcl_recv");
  assert.equal(req.backend, F_foo_backend);
}
