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


// @scope: fetch
sub sas_fetch_akamai_caching(STRING var.mode, INTEGER var.cache_lifetime, INTEGER var.default_maxage, STRING var.force_revalidate_stale, BOOL var.enhanced_rfc_support) {

  // === MODE: CACHE ===
  // Cache content on Akamai platform servers for specified time
  if (var.mode ~ "^cache\z") {
    set beresp.http.X-CacheMode = "cache";
    set beresp.cacheable = true;
    set beresp.ttl = var.cache_lifetime;

    // CRITICAL: Adjust TTL for shield/cluster cached responses
    // When shielding or clustering is enabled, responses from shield/cluster include
    // an Age header indicating how long the object has been cached.
    // We must subtract this from the TTL to maintain correct cache lifetime.
    // Reference: See performance.vcl examples in codebase
    if (beresp.http.Age) {
      set beresp.ttl -= std.atoi(beresp.http.Age);
    }
  }
}


sub vcl_recv {
#FASTLY RECV
  return(pass);
}


sub vcl_fetch {
#FASTLY FETCH
  call sas_fetch_akamai_caching("cache", 3600, 1800, "none", false);
  return(pass);
}
