sub force_restart {
  restart;
}

sub force_error {
  error 800 "FORCE ERROR";
}

sub noop {

}

sub nested {
  set req.http.Foo = "1";
}

sub call_nested {
  call nested;
}

sub vcl_recv {
  return(lookup);
}
