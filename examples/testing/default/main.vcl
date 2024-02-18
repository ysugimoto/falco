backend httpbin_org {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "httpbin.org";
  .first_byte_timeout = 20s;
  .max_connections = 500;
  .between_bytes_timeout = 20s;
  .share_key = "xei5lohleex3Joh5ie5uy7du";
  .ssl = true;
  .ssl_sni_hostname = "httpbin.org";
  .ssl_cert_hostname = "httpbin.org";
  .ssl_check_cert = always;
  .min_tls_version = "1.2";
  .max_tls_version = "1.2";
  .bypass_local_route_table = false;
  .probe = {
    .request = "GET /status/200 HTTP/1.1" "Host: httpbin.org" "Connection: close";
    .dummy = true;
    .threshold = 1;
    .window = 2;
    .timeout = 5s;
    .initial = 1;
    .expected_response = 200;
    .interval = 10s;
  }
}

//@scope: recv,deliver,log
sub custom_logger {
  log req.http.header;
}

sub vcl_recv {

  #Fastly recv
  set req.backend = httpbin_org;
  set req.http.Foo = {" foo bar baz "};
  call custom_logger;

  if (req.http.Check-Auth) {
    error 401;
  }
  return (lookup);
}

sub vcl_deliver {

  #Fastly deliver
  set resp.http.X-Custom-Header = "Custom Header";
  call custom_logger;
  return (deliver);
}

sub vcl_fetch {

  #Fastly fetch
  call custom_logger;
  return(deliver);
}
