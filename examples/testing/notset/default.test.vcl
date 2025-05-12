// All test cases refered to Fastly fiddle behaviors
// see: https://fiddle.fastly.dev/fiddle/68510f85
// see: https://fiddle.fastly.dev/fiddle/93d222ff

describe notset_local_variable {

  // @scope: recv
  sub single_comparison {
    declare local var.state STRING;
    declare local var.S STRING;
    if (!var.S) {
      set var.state = "notset";
    }
    if (var.S == "") {
      set var.state = "empty";
    }
    assert.equal(var.state, "notset");
    assert.equal(std.strlen(var.S), 0);
    assert.equal(var.S, "(null)");
  }

  // @scope: recv
  sub set_empty_string {
    declare local var.state STRING;
    declare local var.S STRING;
    set var.S = "";
    if (!var.S) {
      set var.state = "notset";
    }
    if (var.S == "") {
      set var.state = "empty";
    }
    assert.equal(var.state, "empty");
    assert.equal(std.strlen(var.S), 0);
    assert.equal(var.S, "");
  }

  // @scope: recv
  sub set_notset_http_header {
    declare local var.state STRING;
    declare local var.S STRING;
    set var.S = req.http.Undefined;
    if (!var.S) {
      set var.state = "notset";
    }
    if (var.S == "") {
      set var.state = "empty";
    }
    assert.equal(var.state, "empty");
    assert.equal(std.strlen(var.S), 0);
    assert.equal(var.S, "");
  }

  // @scope: recv
  sub set_doubled_notset_values {
    declare local var.state STRING;
    declare local var.S STRING;
    declare local var.T STRING;
    set var.S = req.http.Undefined var.T;
    if (!var.S) {
      set var.state = "notset";
    }
    if (var.S == "") {
      set var.state = "empty";
    }
    assert.equal(var.state, "empty");
    assert.equal(std.strlen(var.S), 0);
    assert.equal(var.S, "");
  }

  // @scope: recv
  sub set_notset_header_value_with_some_value {
    declare local var.state STRING;
    declare local var.S STRING;
    set var.S = req.http.Undefined "-SomeValue";
    if (!var.S) {
      set var.state = "notset";
    }
    if (var.S == "") {
      set var.state = "empty";
    }
    assert.is_notset(var.state);
    assert.equal(std.strlen(var.S), 10);
    assert.equal(var.S, "-SomeValue");
  }

  // @scope: recv
  sub set_notset_variable_with_some_value {
    declare local var.state STRING;
    declare local var.S STRING;
    declare local var.T STRING;
    set var.S = var.T "-SomeValue";
    if (!var.S) {
      set var.state = "notset";
    }
    if (var.S == "") {
      set var.state = "empty";
    }
    assert.is_notset(var.state);
    assert.equal(std.strlen(var.S), 10);
    assert.equal(var.S, "-SomeValue");
  }

  // @scope: recv
  sub assign_notset_variable {
    declare local var.state STRING;
    declare local var.S STRING;
    declare local var.T STRING;
    set var.S = var.T;
    if (!var.S) {
      set var.state = "notset";
    }
    if (var.S == "") {
      set var.state = "empty";
    }
    assert.equal(var.state, "empty");
    assert.equal(std.strlen(var.S), 0);
    assert.equal(var.S, "");
  }
}

describe notset_http_header {

  before_recv {
    unset req.http.Undefined;
  }

  // @scope: recv
  sub single_comparison {
    declare local var.state STRING;
    if (!req.http.Undefined) {
      set var.state = "notset";
    }
    if (req.http.Undefined == "") {
      set var.state = "empty";
    }
    assert.equal(var.state, "notset");
    assert.equal(std.strlen(req.http.Undefined), 0);
    assert.equal(req.http.Undefined, "(null)");
  }

  // @scope: recv
  sub set_empty_string {
    declare local var.state STRING;
    set req.http.Undefined = "";
    if (!req.http.Undefined) {
      set var.state = "notset";
    }
    if (req.http.Undefined == "") {
      set var.state = "empty";
    }
    assert.equal(var.state, "empty");
    assert.equal(std.strlen(req.http.Undefined), 0);
    assert.equal(req.http.Undefined, "");
  }

  // @scope: recv
  sub set_notset_http_header {
    declare local var.state STRING;
    set req.http.Undefined = req.http.UndefinedHeader;
    if (!req.http.Undefined) {
      set var.state = "notset";
    }
    if (req.http.Undefined == "") {
      set var.state = "empty";
    }
    assert.equal(var.state, "notset");
    assert.equal(std.strlen(req.http.Undefined), 0);
    assert.equal(req.http.Undefined, "(null)");
  }

  // @scope: recv
  sub set_doubled_notset_value {
    declare local var.state STRING;
    declare local var.T STRING;
    set req.http.Undefined = req.http.UndefinedHeader var.T;
    if (!req.http.Undefined) {
      set var.state = "notset";
    }
    if (req.http.Undefined == "") {
      set var.state = "empty";
    }
    assert.equal(var.state, "notset");
    assert.equal(std.strlen(req.http.Undefined), 0);
    assert.equal(req.http.Undefined, "(null)");
  }

  // @scope: recv
  sub set_notset_http_header_with_some_value {
    declare local var.state STRING;
    set req.http.Undefined = req.http.UndefinedHeader "-SomeValue";
    if (!req.http.Undefined) {
      set var.state = "notset";
    }
    if (req.http.Undefined == "") {
      set var.state = "empty";
    }
    assert.is_notset(var.state);
    assert.equal(std.strlen(req.http.Undefined), 16);
    assert.equal(req.http.Undefined, "(null)-SomeValue");
  }

  // @scope: recv
  sub set_notset_variable_with_some_value {
    declare local var.state STRING;
    declare local var.T STRING;
    set req.http.Undefined = var.T "-SomeValue";
    if (!req.http.Undefined) {
      set var.state = "notset";
    }
    if (req.http.Undefined == "") {
      set var.state = "empty";
    }
    assert.is_notset(var.state);
    assert.equal(std.strlen(req.http.Undefined), 16);
    assert.equal(req.http.Undefined, "(null)-SomeValue");
  }

  // @scope: recv
  sub set_notset_http_header_to_local_variable {
    declare local var.state STRING;
    declare local var.V STRING;
    set req.http.Undefined = req.http.UndefinedHeader "-SomeValue";
    set var.V = req.http.Undefined "header";
    if (!req.http.Undefined) {
      set var.state = "notset";
    }
    if (req.http.Undefined == "") {
      set var.state = "empty";
    }
    assert.is_notset(var.state);
    assert.equal(std.strlen(var.V), 22);
    assert.equal(var.V, "(null)-SomeValueheader");
  }
}

describe notset_ip {

  // @scope: recv
  sub notset_output {
    declare local var.S IP;
    assert.equal(std.strlen(var.S), 0);
    assert.equal(var.S, "(null)");
  }

  // @scope: recv
  sub set_notset_ip_to_header {
    declare local var.state STRING;
    declare local var.S IP;
    set req.http.H = var.S;
    if (!req.http.H) {
      set var.state = "notset";
    }
    if (req.http.H) {
      set var.state = "empty";
    }
    assert.equal(var.state, "notset");
    assert.equal(std.strlen(req.http.H), 0);
    assert.equal(req.http.H, "(null)");
  }

  // @scope: recv
  sub set_doubled_notset_values {
    declare local var.state STRING;
    declare local var.S STRING;
    declare local var.T IP;
    set var.S = req.http.Undefined var.T;
    if (!var.S) {
      set var.state = "notset";
    }
    if (var.S == "") {
      set var.state = "empty";
    }
    assert.equal(var.state, "empty");
    assert.equal(std.strlen(var.S), 0);
    assert.equal(var.S, "");
  }

  // @scope: recv
  sub set_notset_ip_with_some_value {
    declare local var.state STRING;
    declare local var.S STRING;
    declare local var.T IP;
    set var.S =  var.T "-SomeValue";
    if (!var.S) {
      set var.state = "notset";
    }
    if (var.S == "") {
      set var.state = "empty";
    }
    assert.is_notset(var.state);
    assert.equal(std.strlen(var.S), 10);
    assert.equal(var.S, "-SomeValue");
  }
}
