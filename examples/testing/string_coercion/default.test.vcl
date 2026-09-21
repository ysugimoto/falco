// The == and != operators coerce the right operand to the type of the left one.
// All expectations below are the values observed on Fastly.
// see: https://fiddle.fastly.dev/fiddle/6c2ac451

describe string_equality_coercion {

  // @scope: recv
  sub integer_operand {
    declare local var.I INTEGER;
    set var.I = 10;
    set req.http.S = "10";
    assert.true(req.http.S == var.I);
    assert.false(req.http.S != var.I);
    set req.http.S = "example";
    assert.false(req.http.S == var.I);
  }

  // @scope: recv
  sub float_operand {
    declare local var.F FLOAT;
    // FLOAT renders with 3 decimal places, so 10.0001 also compares equal
    set var.F = 10.0001;
    set req.http.S = "10.000";
    assert.true(req.http.S == var.F);
    set req.http.S = "10.0001";
    assert.false(req.http.S == var.F);
  }

  // @scope: recv
  sub rtime_operand {
    declare local var.R RTIME;
    set var.R = 100s;
    set req.http.S = "100.000";
    assert.true(req.http.S == var.R);
  }

  // @scope: recv
  sub time_operand {
    declare local var.T TIME;
    set var.T = std.time("Thu, 13 Aug 2026 10:26:36 GMT", now);
    set req.http.S = "Thu, 13 Aug 2026 10:26:36 GMT";
    assert.true(req.http.S == var.T);
    set req.http.S = "example";
    assert.false(req.http.S == var.T);
  }

  // @scope: recv
  sub bool_operand {
    declare local var.B BOOL;
    set var.B = true;
    set req.http.S = "1";
    assert.true(req.http.S == var.B);
    // unlike the other types a BOOL literal is accepted
    // see: https://fiddle.fastly.dev/fiddle/9eb5f06b
    assert.true(req.http.S == true);
    set var.B = false;
    set req.http.S = "0";
    assert.true(req.http.S == var.B);
  }

  // @scope: recv
  sub ip_operand {
    declare local var.IPV IP;
    set var.IPV = "123.123.123.123";
    set req.http.S = "123.123.123.123";
    assert.true(req.http.S == var.IPV);
    set req.http.S = "example";
    assert.false(req.http.S == var.IPV);
  }

  // @scope: recv
  sub backend_operand {
    // a BACKEND compares by name, whether it is a declared backend identifier
    // or obtained from req.backend
    set req.backend = example;
    set req.http.S = "example";
    assert.true(req.http.S == example);
    assert.true(req.http.S == req.backend);
    set req.http.S = "other";
    assert.false(req.http.S == example);
  }
}

describe string_equality_notset {

  // @scope: recv
  sub unset_never_matches {
    declare local var.I INTEGER;
    set var.I = 10;
    unset req.http.Missing;
    assert.false(req.http.Missing == var.I);
    assert.true(req.http.Missing != var.I);
    assert.false(req.http.Missing == req.http.Missing2);
    assert.true(req.http.Missing != req.http.Missing2);
    assert.false(req.http.Missing == "");
  }
}
