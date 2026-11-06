sub vcl_recv {
#FASTLY RECV
  set req.http.X-Example = "hello";
  if (req.url ~ "^/admin") {
    set req.http.X-Admin = "1";
  }
}
