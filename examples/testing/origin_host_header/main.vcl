backend example {
  .host = "example.com";
  .port = "443";
}

backend override_example {
  .host = "example.com";
  .port = "443";
  .always_use_host_header = true;
}

backend dynamic_example {
  .dynamic = true;
  .host = "example.com";
  .port = "443";
}

backend dynamic_override_example {
  .dynamic = true;
  .host = "example.com";
  .port = "443";
  .host_header = "dynamic.example.com";
}
