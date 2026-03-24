backend example_com {
  .host = "example.com";
  .port = "443";
}

backend fastly_com {
  .host = "fastly.com";
  .port = "443";
}

sub vcl_recv {
  #Fastly recv
  if (req.http.Host == "example.com") {
    set req.backend = example_com;
  } else if (req.http.Host == "fastly.com") {
    set req.backend = fastly_com;
  }
  set req.http.X-Routed-Host = req.http.Host;
}
