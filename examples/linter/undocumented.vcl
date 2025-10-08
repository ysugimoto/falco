sub vcl_miss {
  #FASTLY miss
  set bereq.max_reuse_idle_time = 3570s;
}

sub vcl_pass {
  #FASTLY pass
  set bereq.max_reuse_idle_time = 3570s;
}
