describe group {

  before_recv {
    set req.http.Before = "1";
  }

  before_fetch {
    set req.http.Before = "2";
  }

  // @scope: recv
  sub test_recv {
    assert.equal(req.http.Before, "1");
    testing.call_subroutine("vcl_recv");
    assert.equal(req.http.Grouped, "1");
  }

  // @scope: fetch
  sub test_fetch {
    assert.equal(req.http.Before, "2");
  }
}
