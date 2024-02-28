// see: https://github.com/ysugimoto/falco/issues/235

// @scope: recv
// @suite: UNSET header
sub test_recv {
    set req.http.VALUE = "V";
    unset req.http.VALUE;
    assert.is_notset(req.http.VALUE);

    set req.http.MESSAGE = req.http.VALUE;
    assert.is_notset(req.http.MESSAGE);
}

// @scope: recv
// @suite: EMPTY header
sub test_recv {
    set req.http.VALUE = "V";
    set req.http.VALUE = "";
    assert.equal(req.http.VALUE, "");

    set req.http.MESSAGE = req.http.VALUE;
    assert.equal(req.http.MESSAGE, "");
}

// @scope: recv
// @suite: NOTSET header
sub test_recv {
    set req.http.VALUE = "V";
    set req.http.VALUE = req.http.NOTSET;
    assert.is_notset(req.http.VALUE);

    set req.http.MESSAGE = req.http.VALUE;
    assert.is_notset(req.http.MESSAGE);
}
