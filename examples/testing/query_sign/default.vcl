sub vcl_recv {
  set req.url = "/test";
  set req.url = req.url "?";
  set req.url = req.url "foo=bar";
}
