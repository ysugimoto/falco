// @scope: recv
sub test_restart {
  testing.call_subroutine("force_restart");
  assert.restart();
}

// @scope: recv
sub test_error {
  testing.call_subroutine("force_error");
  assert.error(800, "FORCE ERROR");
}

// @scope: recv
sub test_not_error {
  testing.call_subroutine("noop");
  assert.not_error();
}

// @scope: recv
sub test_call_nested {
  testing.call_subroutine("call_nested");
  assert.subroutine_called("nested");
  assert.equal(req.http.Foo, "1");
}

// @scope: recv
sub test_state_check {
  testing.call_subroutine("vcl_recv");
  assert.state(lookup);
}
