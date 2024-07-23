sub mocked {
  set req.http.Mocked = "1";
}

sub mocked_func STRING {
  return "Mocked";
}

describe group {

  before_recv {
    testing.mock("original", "mocked");
    testing.mock("original_func", "mocked_func");
  }

  after_recv {
    testing.restore_all_mocks();
    unset req.http.Mocked;
  }

  // @scope: recv
  sub test_recv {
    testing.call_subroutine("vcl_recv");
    assert.equal(req.http.Mocked, "1");
    assert.is_notset(req.http.Original);
    assert.equal(req.http.FuncValue, "Mocked");
  }

  // @scope: fetch
  sub test_fetch {
    testing.call_subroutine("vcl_fetch");
    assert.equal(req.http.Original, "1");
    assert.is_notset(req.http.Mocked);
    assert.equal(req.http.FuncValue, "Original");
  }

}
