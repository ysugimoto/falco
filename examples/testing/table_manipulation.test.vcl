table test_example {
  "foo": "bar"
}

// @scope: recv
sub test_table_set {
  testing.table_set(example, "foo", "bar");

  testing.call_subroutine("vcl_recv");
  assert.equal(req.http.Foo, "bar");
}

// @scope: recv
sub test_table_merge {
  testing.table_merge(example, test_example);

  testing.call_subroutine("vcl_recv");
  assert.equal(req.http.Foo, "bar");
}
