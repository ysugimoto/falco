// @scope: recv,fetch
sub original {
  set req.http.Original = "1";
}

// @scope: recv,fetch
sub original_func STRING {
  return "Original";
}

sub vcl_recv {
  #FASTLY RECV
  call original;
  set req.http.FuncValue = original_func();
}

sub vcl_fetch {
  #FASTLY FETCH
  call original;
  set req.http.FuncValue = original_func();
}
