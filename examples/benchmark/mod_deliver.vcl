sub mod_deliver {
  // Remove unnecessary header for the client
  unset resp.http.X-Served-By;
  unset resp.http.X-Timer;
  unset resp.http.Via;
  unset resp.http.Age;
  unset resp.http.X-Cache;
  unset resp.http.X-Cache-Hits;
  unset resp.http.Fastly-Restarts;
}
