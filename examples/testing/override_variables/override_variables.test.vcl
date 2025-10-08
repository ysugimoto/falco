// @scope: recv
// @suite: Default variable via function
sub test_default_server_region {
  testing.call_subroutine("vcl_recv");

  assert.equal(req.http.Region, "US");
}

// @scope: recv
// @suite: Override variable via function
sub test_override_server_region {
  testing.inject_variable("server.region", "ASIA");
  testing.call_subroutine("vcl_recv");

  assert.equal(req.http.Region, "ASIA");
}

// @scope: deliver
// @suite: Assert overridden variables via configuration
sub test_override_via_configuration {
  testing.call_subroutine("overrides");

  // bool
  assert.equal(req.http.Is-Cert-Bad, "1");
  // integer
  assert.equal(req.http.Geo-Area-Code, "200");
  // float
  assert.equal(req.http.Digest-Ratio, "0.800");
  // string
  assert.equal(req.http.Client-As-Name, "Foobar");
}

