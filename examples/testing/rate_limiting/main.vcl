ratecounter rc {}
penaltybox pb {}

sub vcl_recv {
  set req.http.Rate-Limit-Exceeded = "0";
  if (ratelimit.check_rate(client.ip, rc, 1, 10, 100, pb, 10s)) {
    set req.http.Rate-Limit-Exceeded = "1";
  }
}
