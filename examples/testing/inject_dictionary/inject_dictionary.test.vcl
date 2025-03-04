// @scope: RECV
// @suite: state should be pass when dictionary is injected
sub test_return_pass {
  testing.call_subroutine("vcl_recv");
  assert.state(pass);
}

