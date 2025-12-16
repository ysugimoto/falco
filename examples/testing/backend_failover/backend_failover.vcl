backend backend1 {
  .host = "backend1.example.com";
  .port = "443";
  .ssl = true;
}

backend backend2 {
  .host = "backend2.example.com";
  .port = "443";
  .ssl = true;
}

backend backend3 {
  .host = "backend3.example.com";
  .port = "443";
  .ssl = true;
}

director my_fallback_director fallback {
  { .backend = backend1; }
  { .backend = backend2; }
  { .backend = backend3; }
}

director my_random_director random {
  .quorum = 50%;
  .retries = 3;
  { .backend = backend1; .weight = 2; }
  { .backend = backend2; .weight = 1; }
  { .backend = backend3; .weight = 1; }
}

sub vcl_recv {
  set req.backend = my_fallback_director;
  return(lookup);
}

