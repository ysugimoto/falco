sub vcl_recv {
  #FASTLY RECV
  set req.http.Grouped = "1";
}
