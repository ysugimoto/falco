// @scope: recv
// @suite: SET VARS VALUE
sub test_recv {
    set req.http.VARS = "";
    set req.http.VARS:VALUE = "V";
    assert.equal(req.http.VARS, "VALUE=V");
}

// @scope: recv
// @suite: SET NOT-INITIALIZED VARS VALUE
sub test_recv {
    set req.http.VARS:VALUE = "V";
    assert.equal(req.http.VARS, "VALUE=V");
}

// @scope: recv
// @suite: SET MULTIPLE VARS VALUE
sub test_recv {
    set req.http.VARS = "";
    set req.http.VARS:VALUE = "V";
    set req.http.VARS:VALUE2 = "V2";
    assert.equal(req.http.VARS, "VALUE=V, VALUE2=V2");
}

// @scope: recv
// @suite: SET EMPTY VARS VALUE
sub test_recv {
    set req.http.VARS = "";
    set req.http.VARS:VALUE = "";
    assert.equal(req.http.VARS, "VALUE");
}

// @scope: recv
// @suite: SET MULTIPLE EMPTY VARS VALUE
sub test_recv {
    set req.http.VARS = "";
    set req.http.VARS:VALUE = "";
    set req.http.VARS:VALUE2 = "";
    assert.equal(req.http.VARS, "VALUE, VALUE2");
}

// @scope: recv
// @suite: UNSET VARS ALL VALUE
sub test_recv {
    set req.http.VARS = "";
    set req.http.VARS:VALUE = "V";
    unset req.http.VARS:VALUE;
    assert.is_notset(req.http.VARS);
}

// @scope: recv
// @suite: UNSET VARS VALUE
sub test_recv {
    set req.http.VARS = "";
    set req.http.VARS:VALUE = "V";
    set req.http.VARS:VALUE2 = "V2";
    unset req.http.VARS:VALUE;
    assert.equal(req.http.VARS, "VALUE2=V2");
}

// @scope: recv
// @suite: OVERRIDE VARS VALUE
sub test_recv {
    set req.http.VARS = "";
    set req.http.VARS:VALUE = "V";
    set req.http.VARS:VALUE = "O";
    assert.equal(req.http.VARS, "VALUE=O");
}

// @scope: recv
// @suite: SET NULL VALUE
sub test_recv {
    set req.http.VARS = "";
    set req.http.VARS:VALUE = "V";
    set req.http.VARS:VALUE = req.http.NULL;
    assert.equal(req.http.VARS, "VALUE");
}
