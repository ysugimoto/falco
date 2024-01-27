// Will be set via testing function
table example {}

sub vcl_recv {
  set req.http.Foo = table.lookup(example, "foo", "");
}
