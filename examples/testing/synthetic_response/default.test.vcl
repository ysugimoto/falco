// @scope: error
sub test_vcl {
  testing.call_subroutine("vcl_error");
  assert.equal(testing.synthetic_body, "No dice.");
  // obj.response could not set after the syntheic response has called.
  assert.is_notset(obj.response);
}
