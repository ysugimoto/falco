// @scope: error
sub test_vcl {
  testing.call_subroutine("vcl_error");
  assert.equal(testing.synthetic_body, "No dice.");
  assert.equal(obj.response, "Overwritten");
}
