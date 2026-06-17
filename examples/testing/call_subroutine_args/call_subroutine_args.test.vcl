// @scope: recv
// @suite: functional BOOL subroutine returns true for first matching path
sub test_path_matches_first {
  set req.url = "/path1/foo";
  declare local var.result BOOL;
  set var.result = testing.call_subroutine("url_path_is_either", "/path1/foo", "/path2/bar");
  assert.true(var.result);
}


// @scope: recv
// @suite: functional BOOL subroutine returns false when path does not match
sub test_path_no_match {
  set req.url = "/other";
  declare local var.result BOOL;
  set var.result = testing.call_subroutine("url_path_is_either", "/path1/foo", "/path2/bar");
  assert.false(var.result);
}


// @scope: recv
// @suite: functional BOOL subroutine returns true for second matching path
sub test_path_matches_second {
  set req.url = "/path2/bar";
  declare local var.result BOOL;
  set var.result = testing.call_subroutine("url_path_is_either", "/path1/foo", "/path2/bar");
  assert.true(var.result);
}


// @scope: recv
// @suite: functional STRING subroutine returns matched for known path
sub test_classify_matched {
  set req.url = "/api/v1";
  declare local var.label STRING;
  set var.label = testing.call_subroutine("classify_path", "/api/v1");
  assert.equal(var.label, "matched");
}


// @scope: recv
// @suite: functional STRING subroutine returns unmatched for unknown path
sub test_classify_unmatched {
  set req.url = "/home";
  declare local var.label STRING;
  set var.label = testing.call_subroutine("classify_path", "/api/v1");
  assert.equal(var.label, "unmatched");
}


// @scope: recv
// @suite: scoped subroutine call without extra args still works
sub test_scoped_subroutine {
  testing.call_subroutine("vcl_recv");
  assert.state(pass);
}


// @scope: fetch
// @suite: fetch subroutine call with extra args still works
sub test_scoped_subroutine_with_args {
  set req.url = "/api/v1";
  testing.call_subroutine("vcl_fetch");
  assert.equal(beresp.cacheable, true);
  assert.state(pass);
}
