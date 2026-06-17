// url_path_is_either returns true when the request path matches
// either of the two provided path strings.
// @scope: recv
sub url_path_is_either(STRING var.path1, STRING var.path2) BOOL {
  if (req.url.path == var.path1 || req.url.path == var.path2) {
    return true;
  }
  return false;
}


// classify_path returns "matched" when the request path equals
// var.expected, otherwise "unmatched".
// @scope: recv
sub classify_path(STRING var.expected) STRING {
  if (req.url.path == var.expected) {
    return "matched";
  }
  return "unmatched";
}


// cache_path returns true when the request path equals var.path
// @scope: fetch
sub cache_path(STRING var.mode, STRING var.path) BOOL {
  if (var.mode ~ "^cache\z" && req.url.path == var.path) {
    set beresp.cacheable = true;
    set beresp.ttl = 3600s;
    return true;
  }
  return false;
}


sub vcl_recv {
#FASTLY RECV
  return(pass);
}


sub vcl_fetch {
#FASTLY FETCH
  call cache_path("cache", "/api/v1");
  return(pass);
}
