## Include dependent modules
include "mod_recv";
include "mod_fetch";
include "mod_deliver";


## Example backend declarations
backend httpbin_org {
  .connect_timeout          = 1s;
  .dynamic                  = true;
  .port                     = "443";
  .host                     = "httpbin.org";
  .first_byte_timeout       = 20s;
  .max_connections          = 500;
  .between_bytes_timeout    = 20s;
  .share_key                = "xei5lohleex3Joh5ie5uy7du";
  .ssl                      = true;
  .ssl_sni_hostname         = "httpbin.org";
  .ssl_cert_hostname        = "httpbin.org";
  .ssl_check_cert           = always;
  .min_tls_version          = "1.2";
  .max_tls_version          = "1.2";
  .bypass_local_route_table = false;
  .probe                    = {
    .request           = "GET /status/200 HTTP/1.1" "Host: httpbin.org" "Connection: close";
    .dummy             = true;
    .threshold         = 1;
    .window            = 2;
    .timeout           = 5s;
    .initial           = 1;
    .expected_response = 200;
    .interval          = 10s;
  }
}


backend example_com {
  .between_bytes_timeout = 10s;
  .connect_timeout       = 1s;
  .dynamic               = true;
  .first_byte_timeout    = 15s;
  .host                  = "example.com";
  .max_connections       = 200;
  .port                  = "443";
  .share_key             = "qRK2E1vLIVkQ3BU0iVk9X7";

  .ssl               = true;
  .ssl_cert_hostname = "example.com";
  .ssl_check_cert    = always;
  .ssl_sni_hostname  = "example.com";

  .probe = {
    .dummy     = true;
    .initial   = 5;
    .request   = "HEAD / HTTP/1.1" "Host: example.com" "Connection: close";
    .threshold = 1;
    .timeout   = 2s;
    .window    = 5;
  }
}


## Example Access Control List
acl internal_ips {
  "10.1.0.0"/18; # Common VPC CIDR
  "192.168.0.0"/18; # Local Machine-like CIDR

  "10.2.0.0"; # IP address only
}


## Example Table declaration
table api_keys STRING {
  "Bahdohngiezu,obeiChi2laejeicangiV3oh": "service01",
  "chie5ahNgieghoow2queeFohM1ao8aez^ae7": "service01",
  "neihuNae/roo1ies5bo{paepo4Wi7eeseiNg": "service02",
  "Ciewoo8oos3foh6ue1Oqu*oo6ohc6tohng|i": "service03",
}


## Example Director declaration
director random_origin random {
  { .backend = httpbin_org; .weight = 2; }
  { .backend = example_com; .weight = 1; }
}


## Subroutines

sub vcl_recv {

#FASTLY recv

  if (req.restarts == 0) {
    set req.http.StateStack = "recv";
  }

  call mod_recv;

  ## Routing
  if (req.url ~ "^/httpbin") {
    set req.backend = httpbin_org;
  }
  else if (req.url ~ "^/example") {
    set req.backend = example_com;
  }
  else if (req.url ~ "^/random") {
    set req.backend = random_origin;
  }
  else {
    error 404;
  }

  # Check the request is cacheable
  if (req.method != "HEAD" && req.method != "GET" && req.method != "FASTLYPURGE") {
    return(pass);
  }
  else {
    return(lookup);
  }
}


sub vcl_hit {

#FASTLY hit

  set req.http.StateStack = req.http.StateStack "->hit";
  return(deliver);
}


sub vcl_miss {

#FASTLY miss

  set req.http.StateStack = req.http.StateStack "->miss";
  return(fetch);
}


sub vcl_fetch {

#FASTLY fetch

  set req.http.StateStack = req.http.StateStack "->fetch";

  call mod_fetch;

  if (beresp.ttl == 0s) {
    return(pass);
  }
  else {
    return(deliver);
  }
}


sub vcl_pass {

#FASTLY pass

  set req.http.StateStack = req.http.StateStack "->pass";
  return(pass);
}


sub vcl_deliver {

#FASTLY deliver

  set req.http.StateStack = req.http.StateStack "->deliver";
  set resp.http.FastlyStateFlow = req.http.StateStack;

  call mod_deliver;

  return(deliver);
}


sub vcl_error {

#FASTLY error

  set req.http.StateStack = req.http.StateStack "->error";
  if (obj.status == 404) {
    synthetic {"Not Found"};
  }
  else if (obj.status == 403) {
    synthetic {"Forbidden"};
  }
  else if (obj.status == 401) {
    synthetic {"Unauthorized"};
  }

  return(deliver);
}


sub vcl_log {

#FASTLY log

  log {"syslog "} req.service_id {" fastly-log :: "} {" method: "} req.method {" url: "} req.url
      {" status: "} resp.status;
}
