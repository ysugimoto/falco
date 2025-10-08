backend example_com {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "example.com";
  .first_byte_timeout = 20s;
  .max_connections = 500;
  .between_bytes_timeout = 20s;
  .share_key = "xei5lohleex3Joh5ie5uy7du";
  .ssl = true;
  .ssl_sni_hostname = "example.com";
  .ssl_cert_hostname = "example.com";
  .ssl_check_cert = always;
  .min_tls_version = "1.2";
  .max_tls_version = "1.2";
  .bypass_local_route_table = false;
  .probe = {
    .request = "GET / HTTP/1.1" "Host: example.com" "Connection: close";
    .dummy = true;
    .threshold = 1;
    .window = 2;
    .timeout = 5s;
    .initial = 1;
    .expected_response = 200;
    .interval = 10s;
  }
}

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
    .request = "GET / HTTP/1.1" "Host: httpbin.org" "Connection: close";
    .dummy = true;
    .threshold = 1;
    .window = 2;
    .timeout = 5s;
    .initial = 1;
    .expected_response = 200;
    .interval = 10s;
  }
}

director example_director random {
  .retries = 3;
  { .backend = example_com; .weight = 1; }
  { .backend = httpbin_org; .weight = 1; }
}

table example_table STRING {
  "lorem": "ipsum",
  "dolor": "sit",
}

sub vcl_recv {

  #Fastly recv
  set req.http.Foo = {" foo bar baz "};

  if (!req.http.Host) {
    set req.backend = example_director;
    set req.http.Host = "example.com";
  } else if (req.http.Host == "example.com") {
    set req.backend = httpbin_org;
    set req.http.Host = "httpbin.org";
  } else {
    set req.backend = example_com;
    set req.http.Host = "example.com";
  }
  return (pass);
}

sub vcl_deliver {

  #Fastly deliver
  if (req.http.Header1 == "1" && req.http.Header2 == "2" && req.http.Header3 == "3" && req.http.Header4 == "4") {
    set resp.http.Matched = "yes";
  }

  set resp.http.X-Custom-Header = "Custom Header";
  return (deliver);
}

sub vcl_fetch {

  #Fastly fetch
  return(deliver);
}

sub vcl_error {

  #Fastly error
  synthetic {"Synthetic error response."};
}


sub vcl_log {

  #Fastly log
  log {"lorem ipsum "} req.http.Host client.os.name {" dolor sit amet."};
}
