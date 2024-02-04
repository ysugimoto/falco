// Note: using an unusual assert setup in these tests to ensure the results
// of the test match the expectations without relying on the `Value.String()`
// calls used in `assert.equal()`.

// @suite: Set STRING var the result of concatenation of an unset STRING var and unset STRING var
sub test_set_concat_unset_strings {
  declare local var.str STRING;
  declare local var.unset STRING;
  set var.str = var.unset + var.unset;
  log "concat unset strings:";
  if (var.str == "") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "(null)(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set STRING var the result of concatenation of a string literal and unset STRING var
sub test_set_concat_unset_string {
  declare local var.str STRING;
  declare local var.unset STRING;
  set var.str = "left" + var.unset;
  log "concat unset string (left):";
  if (var.str == "left") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "left(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
  set var.str = var.unset + "right";
  log "concat unset string (right):";
  if (var.str == "right") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "(null)right") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set STRING var the result of concatenation of a string literal and unset IP var
sub test_set_concat_unset_ip {
  declare local var.str STRING;
  declare local var.unset IP ;
  set var.str = "left" + var.unset;
  log "concat unset IP (left):";
  if (var.str == "left") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "left(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
  set var.str = var.unset + "right";
  log "concat unset IP (right):";
  if (var.str == "right") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "(null)right") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set STRING var the result of space concatenation of an unset STRING var and unset STRING var
sub test_set_space_concat_unset_strings {
  declare local var.str STRING;
  declare local var.unset STRING;
  set var.str = var.unset var.unset;
  log "concat unset strings:";
  if (var.str == "") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "(null)(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set STRING var the result of space concatenation of a string literal and unset STRING var
sub test_set_space_concat_unset_string {
  declare local var.str STRING;
  declare local var.unset STRING;
  set var.str = "left" var.unset;
  log "concat unset string (left):";
  if (var.str == "left") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "left(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
  set var.str = var.unset "right";
  log "concat unset string (right):";
  if (var.str == "right") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "(null)right") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set STRING var the result of space concatenation of a string literal and unset IP var
sub test_set_space_concat_unset_ip {
  declare local var.str STRING;
  declare local var.unset IP;
  set var.str = "left" var.unset;
  log "concat unset IP (left):";
  if (var.str == "left") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "left(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
  set var.str = var.unset "right";
  log "concat unset IP (right):";
  if (var.str == "right") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "(null)right") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set STRING var the result of concatenation of a string literal and unset header
sub test_set_concat_unset_header {
  declare local var.str STRING;
  set var.str = "left" + req.http.unset;
  log "concat unset header (left):";
  if (var.str == "left") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "left(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
  set var.str = req.http.unset + "right";
  log "concat unset header (right):";
  if (var.str == "right") {
    log "empty string (expected)"; //correct
    assert.true(true);
  } else if (var.str == "(null)right") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set STRING var the result of space concatenation of a string literal and unset header
sub test_set_space_concat_unset_header {
  declare local var.str STRING;
  set var.str = "left" req.http.unset;
  log "set space concat unset header (left):";
  if (var.str == "left") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "left(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
  set var.str = req.http.unset "right";
  log "set space concat unset header (right):";
  if (var.str == "right") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "(null)right") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set header the result of concatenation of a string literal and unset STRING var 
sub test_set_header_concat_unset_string {
  declare local var.unset STRING;
  log "set header concat unset string (left):";
  set req.http.unset_string = "left" + var.unset;
  if (req.http.unset_string == "left") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.unset_string == "left(null)") {
    log "(null) (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: (null)");
  }
  log "set header concat unset string (right):";
  set req.http.unset_string = var.unset + "right";
  if (req.http.unset_string == "right") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.unset_string == "(null)right") {
    log "(null) (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: (null)");
  }
}

// @suite: Set header the result of concatenation of a string literal and unset IP var 
sub test_set_header_concat_unset_ip {
  declare local var.unset IP;
  log "set header concat unset ip (left):";
  set req.http.unset_ip = "left" + var.unset;
  if (req.http.unset_ip == "left") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.unset_ip == "left(null)") {
    log "(null) (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: (null)");
  }
  log "set header concat unset ip (right):";
  set req.http.unset_ip = var.unset + "right";
  if (req.http.unset_ip == "right") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.unset_ip == "(null)right") {
    log "(null) (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: (null)");
  }
}

// @suite: Set header the result of concatenation of a string literal and header
sub test_set_header_concat_unset_header {
  log "set header concat unset header (left):";
  set req.http.concat_unset_header = "left" + req.http.unset;
  if (req.http.concat_unset_header == "left") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.concat_unset_header == "left(null)") {
    log "(null) (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: (null)");
  }
  log "set header concat unset header (right):";
  set req.http.concat_unset_header = req.http.unset + "right";
  if (req.http.concat_unset_header == "right") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.concat_unset_header == "(null)right") {
    log "(null) (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: (null)");
  }
}

// @suite: Add header the result of concatenation of a string literal and unset header
sub test_add_header_concat_unset_header {
  log "add header concat unset header (left):";
  add req.http.add_concat_unset_header_left = "left" + req.http.unset;
  if (req.http.add_concat_unset_header_left == "left") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.add_concat_unset_header_left == "left(null)") {
    log "(null) (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: (null)");
  }
  log "add header concat unset header (right):";
  add req.http.add_concat_unset_header_right = req.http.unset + "right";
  if (req.http.add_concat_unset_header_right == "right") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.add_concat_unset_header_right == "(null)right") {
    log "(null) (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: (null)");
  }
}

// @suite: Add header the result of concatenation of a string literal and unset STRING var
sub test_add_header_concat_unset_string {
  log "add header concat unset string (left):";
  declare local var.unset STRING;
  add req.http.add_concat_unset_string_left = "left" + var.unset;
  if (req.http.add_concat_unset_string_left == "left") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.add_concat_unset_string_left == "left(null)") {
    log "(null) (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: (null)");
  }
  log "add header concat unset string (right):";
  add req.http.add_concat_unset_string_right = var.unset + "right";
  if (req.http.add_concat_unset_string_right == "right") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.add_concat_unset_string_right == "(null)right") {
    log "(null) (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: (null)");
  }
}

// @suite: Add header the result of concatenation of a string literal and unset IP var
sub test_add_header_concat_unset_ip {
  log "add header concat unset ip (left):";
  declare local var.unset IP;
  add req.http.add_concat_unset_ip_left = "left" + var.unset;
  if (req.http.add_concat_unset_ip_left == "left") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.add_concat_unset_ip_left == "left(null)") {
    log "(null) (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: (null)");
  }
  log "add header concat unset ip (right):";
  add req.http.add_concat_unset_ip_right = var.unset + "right";
  if (req.http.add_concat_unset_ip_right == "right") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.add_concat_unset_ip_right == "(null)right") {
    log "(null) (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: (null)");
  }
}

// @suite: Set header an unset STRING var
sub test_set_header_unset_string {
  declare local var.unset STRING;
  log "set header unset string:";
  set req.http.unset_string = var.unset;
  if (req.http.unset_string == "") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.unset_string == "(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "not_set (expected)"; // correct
    assert.true(true);
  }
}

// @suite: Set header an unset IP var
sub test_set_header_unset_ip {
  declare local var.unset IP;
  log "set header unset ip:";
  set req.http.unset_ip = var.unset;
  if (req.http.unset_ip == "") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.unset_ip == "(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else if (!req.http.unset_ip) {
    log "not_set (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: not set");
  }
}

// @suite: Set header an unset header
sub test_set_header_unset_header {
  log "set header unset header:";
  set req.http.unset_header = req.http.unset_123;
    if (req.http.unset_header == "") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.unset_header == "(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else if (!req.http.unset_header) {
    log "not_set (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: not set");
  }
}

// @suite: Add header an unset header
sub test_add_header_unset_header {
  log "add header unset header:";
  add req.http.unset_header = req.http.unset_123;
    if (req.http.unset_header == "") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.unset_header == "(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else if (!req.http.unset_header) {
    log "not_set (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: not set");
  }
}

// @suite: Add header an unset STRING
sub test_add_header_unset_string {
  log "add header unset ip:";
  declare local var.unset STRING;
  add req.http.unset_header = var.unset;
    if (req.http.unset_header == "") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.unset_header == "(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else if (!req.http.unset_header) {
    log "not_set (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: not set");
  }
}

// @suite: Add header an unset IP
sub test_add_header_unset_ip {
  log "add header unset ip:";
  declare local var.unset IP;
  add req.http.unset_header = var.unset;
    if (req.http.unset_header == "") {
    log "empty string";
    assert.true(false, "got: empty string, expected: (null)");
  } else if (req.http.unset_header == "(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else if (!req.http.unset_header) {
    log "not_set (expected)"; // correct
    assert.true(true);
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: not set");
  }
}
// @suite: Set STRING var an unset STRING var 
sub test_set_string_unset_string {
  declare local var.str STRING;
  declare local var.unset STRING;
  log "set local unset string:";
  set var.str = var.unset;
  if (var.str == "") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else if (!var.str) {
    log "not_set";
    assert.true(false, "got: not set, expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set STRING var an unset IP var 
sub test_set_string_unset_ip {
  declare local var.str STRING;
  declare local var.unset IP;
  log "set local unset IP:";
  set var.str = var.unset;
  if (var.str == "") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else if (!var.str) {
    log "not_set";
    assert.true(false, "got: not set, expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set STRING var an unset header
sub test_set_string_unset_header {
  declare local var.str STRING;
  log "set local unset header:";
  set var.str = req.http.unset;
  if (var.str == "") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else if (!var.str) {
    log "not_set";
    assert.true(false, "got: not set, expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set STRING var result of json.escape with unset STRING argument
sub test_set_jsonescape {
  declare local var.str STRING;
  declare local var.unset STRING;
  log "set local var result of json.escape with unset argument";
  set var.str = json.escape(var.unset);
    if (var.str == "") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else if (!var.str) {
    log "not_set";
    assert.true(false, "got: not set, expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set STRING var result of regsub with unset STRING replacement argument
sub test_set_regsub {
  declare local var.str STRING;
  declare local var.unset STRING;
  log "set local var result of regsub test_with unset replacement";
  set var.str = regsub("bar baz", "a", var.unset);
  if (var.str == "br baz") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "b(null)r baz") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Set STRING var result of json.escape with string concatenation argument containing an unset STRING
sub test_concat_in_function_argument {
  declare local var.str STRING;
  declare local var.unset STRING;
  log "set local var result of json.escape with concat of string and unset argument";
  set var.str = json.escape(var.unset + "foo");
  if (var.str == "foo") {
    log "empty string (expected)"; // correct
    assert.true(true);
  } else if (var.str == "(null)foo") {
    log "(null)";
    assert.true(false, "got: (null), expected: empty string");
  } else {
    log "no match";
    assert.true(false, "got: no match, expected: empty string");
  }
}

// @suite: Use unset STRING variable as switch statement control
sub test_switch_statement_unset_string {
  log "unset string in switch control";
  declare local var.unset STRING;
  switch (var.unset) {
    case "":
      log "empty string (expected)"; // correct
      assert.true(true);
      break;
    case "(null)":
      log "(null)";
      assert.true(false, "got: (null), expected: empty string");
      break;
    default:
      log "no match";
      assert.true(false, "got: no match, expected: empty string");
      break;
  }
}

// @suite: Use unset IP variable as switch statement control
sub test_switch_statement_unset_ip {
  log "unset ip in switch control";
  declare local var.unset IP;
  switch (var.unset) {
    case "":
      log "empty string (expected)"; // correct
      assert.true(true);
      break;
    case "(null)":
      log "(null)";
      assert.true(false, "got: (null), expected: empty string");
      break;
    default:
      log "no match";
      assert.true(false, "got: no match, expected: empty string");
      break;
  }
}


// @suite: Use unset header as switch statement control
sub test_switch_statement_unset_header {
  log "unset header in switch control";
  switch (req.http.unset) {
    case "":
      log "empty string (expected)"; // correct
      assert.true(true);
      break;
    case "(null)":
      log "(null)";
      assert.true(false, "got: (null), expected: empty string");
      break;
    default:
      log "no match";
      assert.true(false, "got: no match, expected: empty string");
      break;
  }
}

// @suite: Unset STRING variable in if statement condition
sub test_if_statement_unset_string {
  log "if statement unset string condition";
  declare local var.unset STRING;
  if (var.unset == "") {
    log "empty string";
    assert.true(false, "got: empty string, expected: false");
  } else if (var.unset == "(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: false");
  } else if (!var.unset) {
    log "false (expected)";
    assert.true(true);
  }
}

// @suite: Unset header in if statement condition
sub test_if_statement_unset_header {
  log "if statement unset header condition";
  if (req.http.unset == "") {
    log "empty string";
    assert.true(false, "got: empty string, expected: false");
  } else if (req.http.unset == "(null)") {
    log "(null)";
    assert.true(false, "got: (null), expected: false");
  } else if (!req.http.unset) {
    log "false (expected)";
    assert.true(true);
  }
}

// Need #249 to be able to properly validate the remaining tests.
// For now they show in the fiddle how Fastly handles not set values
// in log statements.

// @suite: Log statement with unset STRING variable
sub test_log_statement_unset_string {
    log "log statement with unset string";

    declare local var.unset STRING;

    log "var.unset:";

    log "direct ident";
    log var.unset;
    log "expect: (null)";

    log "space concat";
    log var.unset "foo";
    log "expect: (null)foo";

    log "+ concat";
    log var.unset + "foo";
    log "expect: (null)foo";

    log "req.http.unset:";

    log "direct ident";
    log req.http.unset;
    log "expect: (null)";

    log "space concat";
    log req.http.unset "foo";
    log "expect: (null)foo";

    log "+ concat";
    log req.http.unset + "foo";
    log "expect: (null)foo";
}

// @suite: Log statement with unset IP variable
sub test_log_statement_unset_ip {
    log "log statement with unset IP";

    declare local var.unset IP;
    log "var.unset:";

    log "direct ident";
    log var.unset;
    log "expect: (null)";

    log "space concat";
    log var.unset "foo";
    log "expect: (null)foo";

    log "+ concat";
    log var.unset + "foo";
    log "expect: (null)foo";

    log "req.http.unset:";

    log "direct ident";
    log req.http.unset;
    log "expect: (null)";

    log "space concat";
    log req.http.unset "foo";
    log "expect: (null)foo";

    log "+ concat";
    log req.http.unset + "foo";
    log "expect: (null)foo";
}

// @suite: Log statement with unset header
sub test_log_statement_unset_header {
    log "log statement with unset header";

    log "req.http.unset:";

    log "direct ident";
    log req.http.unset;
    log "expect: (null)";

    log "space concat";
    log req.http.unset "foo";
    log "expect: (null)foo";

    log "+ concat";
    log req.http.unset + "foo";
    log "expect: (null)foo";

    log "req.http.unset:";

    log "direct ident";
    log req.http.unset;
    log "expect: (null)";

    log "space concat";
    log req.http.unset "foo";
    log "expect: (null)foo";

    log "+ concat";
    log req.http.unset + "foo";
    log "expect: (null)foo";
}
