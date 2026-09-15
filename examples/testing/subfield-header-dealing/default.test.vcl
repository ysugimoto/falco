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
    assert.equal(req.http.VARS, "VALUE=V,VALUE2=V2");
}

// @scope: recv
// @suite: SET EMPTY VARS VALUE
sub test_recv {
    set req.http.VARS = "";
    set req.http.VARS:VALUE = "";
    assert.equal(req.http.VARS, "VALUE");
}

// @scope: recv
// @suite: SET MULTIPLE EMPTY VARS VALUE AND SET ACTUAL STRING
sub test_recv {
    set req.http.VARS = "";
    set req.http.VARS:VALUE = "";
    set req.http.VARS:VALUE2 = "";
    assert.equal(req.http.VARS, "VALUE,VALUE2");

    set req.http.VARS:VALUE = "V";
    assert.equal(req.http.VARS, "VALUE2,VALUE=V");
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

// Reading a subfield distinguishes "not set" from a defined empty string.
// Fastly only treats not-set strings as falsy, so an absent subfield of a
// header that is itself defined must still read as not set.
// All test cases referred to Fastly fiddle behaviors
// see: https://fiddle.fastly.dev/fiddle/28404963

// @scope: recv
// @suite: GET UNDEFINED VARS VALUE FROM EMPTY VARS
sub test_recv {
    declare local var.state STRING;
    set req.http.VARS = "";
    if (req.http.VARS:VALUE) {
        set var.state = "truthy";
    } else {
        set var.state = "falsy";
    }
    assert.equal(var.state, "falsy");
    assert.is_notset(req.http.VARS:VALUE);
}

// @scope: recv
// @suite: GET EMPTY VARS ITSELF
sub test_recv {
    declare local var.state STRING;
    set req.http.VARS = "";
    if (req.http.VARS) {
        set var.state = "truthy";
    } else {
        set var.state = "falsy";
    }
    assert.equal(var.state, "truthy");
    assert.equal(req.http.VARS, "");
}

// @scope: recv
// @suite: GET VARS VALUE OF BARE KEY WITHOUT VALUE
sub test_recv {
    declare local var.state STRING;
    set req.http.BARE = "VALUE";
    if (req.http.BARE:VALUE) {
        set var.state = "truthy";
    } else {
        set var.state = "falsy";
    }
    assert.equal(var.state, "truthy");
    assert.equal(req.http.BARE:VALUE, "");
}

// @scope: recv
// @suite: GET UNDEFINED VARS VALUE FROM NOT-INITIALIZED VARS
sub test_recv {
    declare local var.state STRING;
    if (req.http.NOTSET:VALUE) {
        set var.state = "truthy";
    } else {
        set var.state = "falsy";
    }
    assert.equal(var.state, "falsy");
    assert.is_notset(req.http.NOTSET:VALUE);
}

// @scope: recv
// @suite: GET UNDEFINED VARS VALUE WHEN ANOTHER KEY EXISTS
sub test_recv {
    declare local var.state STRING;
    set req.http.OTHER = "OTHER=O";
    if (req.http.OTHER:VALUE) {
        set var.state = "truthy";
    } else {
        set var.state = "falsy";
    }
    assert.equal(var.state, "falsy");
    assert.is_notset(req.http.OTHER:VALUE);
}

// @scope: recv
// @suite: GET VARS VALUE WITH EXPLICIT EMPTY VALUE
sub test_recv {
    declare local var.state STRING;
    set req.http.EMPTYVAL = "VALUE=";
    if (req.http.EMPTYVAL:VALUE) {
        set var.state = "truthy";
    } else {
        set var.state = "falsy";
    }
    assert.equal(var.state, "truthy");
    assert.equal(req.http.EMPTYVAL:VALUE, "");
}

// @scope: recv
// @suite: ASSIGN UNDEFINED VARS VALUE TO ANOTHER HEADER
sub test_recv {
    declare local var.state STRING;
    set req.http.VARS = "";
    set req.http.COPY = req.http.VARS:VALUE;
    if (req.http.COPY) {
        set var.state = "truthy";
    } else {
        set var.state = "falsy";
    }
    assert.equal(var.state, "falsy");
    assert.is_notset(req.http.COPY);
}
