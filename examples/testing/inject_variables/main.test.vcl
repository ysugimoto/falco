// @scope: recv
// @suite: foo
sub test_vcl_recv {
  testing.inject_variable("client.geo.country_code", "JP");
  testing.call_subroutine("vcl_recv");
  assert.state(pass);
}
