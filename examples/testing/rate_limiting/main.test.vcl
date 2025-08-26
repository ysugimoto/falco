sub test_recv {
  testing.set_access_rate(100);
  testing.call_subroutine("vcl_recv");
  assert.equal(req.http.Rate-Limit-Exceeded, "1");
}
