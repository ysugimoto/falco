// @scope: recv
sub test_recv_upgrade {
  set req.http.X-Upgrade = "websocket";
  testing.call_subroutine("vcl_recv");
  assert.state(upgrade);
}

// @scope: recv
sub test_recv_no_upgrade {
  testing.call_subroutine("vcl_recv");
  assert.not_state(upgrade);
  assert.state(lookup);
}
