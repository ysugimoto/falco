sub test_recv {
  assert.equal(testing.origin_host_header, "localhost");
}

sub test_example {
  set req.backend = example;
  assert.equal(testing.origin_host_header, "localhost");
}

sub test_override_example {
  set req.backend = override_example;
  assert.equal(testing.origin_host_header, "example.com");
}

sub test_dynamic_example {
  set req.backend = dynamic_example;
  assert.equal(testing.origin_host_header, "localhost");
}

sub test_dynamic_override_example {
  set req.backend = dynamic_override_example;
  assert.equal(testing.origin_host_header, "dynamic.example.com");
}
