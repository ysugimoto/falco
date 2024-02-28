// see: https://github.com/ysugimoto/falco/issues/237

// @scope: recv
// @suite: ADD header(add-add-add) BUGGY
sub test_recv {
    add req.http.VALUE = "V1";
    add req.http.VALUE = "V2";
    add req.http.VALUE = "V3";
    assert.equal(req.http.VALUE, "V1");  # request upstream with 3 line headers

    set req.http.MESSAGE = req.http.VALUE;  # set first header value
    assert.equal(req.http.MESSAGE, "V1");
}

// @scope: recv
// @suite: ADD header(set-add-add) BUGGY
sub test_recv {
    set req.http.VALUE = "V1";
    add req.http.VALUE = "V2";
    add req.http.VALUE = "V3";
    assert.equal(req.http.VALUE, "V1");  # request upstream with 3 headers

    set req.http.MESSAGE = req.http.VALUE;  # set first header value
    assert.equal(req.http.MESSAGE, "V1");
}

// @scope: recv
// @suite: ADD header(add-add-set)
sub test_recv {
    add req.http.VALUE = "V1";
    add req.http.VALUE = "V2";
    set req.http.VALUE = "V3";
    assert.equal(req.http.VALUE, "V3");  # 1 header

    set req.http.MESSAGE = req.http.VALUE;
    assert.equal(req.http.MESSAGE, "V3");
}

// @scope: recv
// @suite: UNSET header(add-add-unset)
sub test_recv {
    add req.http.VALUE = "V1";
    add req.http.VALUE = "V2";
    unset req.http.VALUE;
    assert.is_notset(req.http.VALUE);  # 0 header

    set req.http.MESSAGE = req.http.VALUE;
    assert.is_notset(req.http.MESSAGE);
}
