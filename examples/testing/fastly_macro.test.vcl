// @scope: recv
sub vcl_recv_test {
  testing.call_subroutine("vcl_recv");
  assert.starts_with(req.http.X-Timer, "S");
}

// @scope: pass
sub vcl_pass_test {
  testing.call_subroutine("vcl_pass");
  assert.equal(req.http.Fastly-Cachetype, "PASS");
}

// @scope: hit
sub vcl_hit_test {
  testing.call_subroutine("vcl_hit");
  assert.equal(req.http.Fastly-Cachetype, "HIT");
}

// @scope: miss
sub vcl_miss_test {
  testing.call_subroutine("vcl_miss");
  assert.equal(req.http.Fastly-Cachetype, "MISS");
}

// @scope: hash
sub vcl_hash_test {
  testing.call_subroutine("vcl_hash");
  assert.ends_with(req.hash, "1");
}

// @scope: fetch
sub vcl_fetch_test {
  testing.call_subroutine("vcl_fetch");
  assert.starts_with(beresp.http.Fastly-Debug-Path, "(F");
}

// @scope: error
sub vcl_error_test {
  set obj.status = 801;
  testing.call_subroutine("vcl_error");
  assert.equal(obj.status, 301);
}

// @scope: deliver
sub vcl_deliver_test {
  set req.http.X-Timer = "S";
  testing.call_subroutine("vcl_deliver");
  assert.starts_with(resp.http.X-Timer, "S,VE");
}
