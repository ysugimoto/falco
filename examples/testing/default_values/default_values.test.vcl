// @scope: recv
// @suite: EMPTY var
sub test_empty_recv {
  declare local var.is_null BOOL;
  declare local var.is_empty BOOL;
  declare local var.is_equal BOOL;

  declare local var.EMPTY STRING;
  set var.EMPTY = "";

  if (!var.EMPTY) {
    set var.is_null = true;
  } else {
    set var.is_null = false;
  }
  if (var.EMPTY == "") {
    set var.is_empty = true;
  } else {
    set var.is_empty = false;
  }
  if (var.EMPTY == var.EMPTY) {
    set var.is_equal = true;
  } else {
    set var.is_equal = false;
  }
  assert.equal(std.strlen(var.EMPTY), 0);
  assert.false(var.is_null);
  assert.true(var.is_empty);
  assert.true(var.is_equal);
}

// @scope: recv
// @suite: NOTSET var
sub test_notset_recv {
  declare local var.is_null BOOL;
  declare local var.is_empty BOOL;
  declare local var.is_equal BOOL;

  declare local var.NOTSET STRING;

  if (!var.NOTSET) {
    set var.is_null = true;
  } else {
    set var.is_null = false;
  }
  if (var.NOTSET == "") {
    set var.is_empty = true;
  } else {
    set var.is_empty = false;
  }
  if (var.NOTSET == var.NOTSET) {
    set var.is_equal = true;
  } else {
    set var.is_equal = false;
  }
  assert.equal(std.strlen(var.NOTSET), 0);
  assert.true(var.is_null);
  assert.false(var.is_empty);
  assert.false(var.is_equal);
}

// @scope: recv
// @suite: default value check
sub test_default_local_var_recv {
  declare local var.is_null BOOL;

  declare local var.bool BOOL;
  declare local var.integer INTEGER;
  declare local var.float FLOAT;
  declare local var.string STRING;
  declare local var.time TIME;
  declare local var.rtime RTIME;
  declare local var.ip IP;

  assert.false(var.bool);
  assert.equal(var.integer, 0);
  assert.equal(var.float, 0.000);
  assert.equal(var.time, std.time("Thu, 01 Jan 1970 00:00:00 GMT", now));
  assert.equal(var.rtime, 0s);

  if (!var.string) {
    set var.is_null = true;
  } else {
    set var.is_null = false;
  }
  assert.true(var.is_null);
  assert.equal(var.string, "");
}

// @scope: recv
// @suite: NotSet http header
sub test_http_header_value {
  declare local var.is_null BOOL;

  if (!req.http.UndefinedHeader) {
    set var.is_null = true;
  } else {
    set var.is_null = false;
  }
  assert.true(var.is_null);
}
