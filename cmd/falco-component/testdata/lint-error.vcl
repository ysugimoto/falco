sub vcl_recv {
#FASTLY RECV
  set req.http.X-Bad = obj.does_not_exist;
  call undefined_subroutine;
}
