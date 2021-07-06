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

sub vcl_recv {

  #Fastly recv
  set req.backend = httpbin_org;

  return (pass);
}

sub vcl_deliver {

  #Fastly deliver
  set resp.http.X-Custom-Header = "Custom Header";
  return (deliver);
}

sub vcl_fetch {

  error 755 "/login?s=error";

  #Fastly fetch
  return(deliver);
}

sub vcl_error {

  #Fastly error
  if (obj.status == 755) {
    set obj.http.Location = regsub(obj.response, "^([^;]*)(;.*)?$", "\1");
    set obj.response = "Found";
    set obj.status = 302;
  }

  return(deliver);
}
