sub mod_fetch {
  // httpbin.org request should not cache the origin response
  if (req.backend == httpbin_org) {
    set beresp.ttl = 0s;
    set beresp.http.Cache-Control = "no-cache";
  }
  else {
    set beresp.ttl = 300s; // 5min cache as usual
    set beresp.stale_while_revalidate = 240s;
  }
}
