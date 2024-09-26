// https://fiddle.fastly.dev/fiddle/a3b006c4

// @scope: recv
// @suite: Test base64 decode
sub test_base64_decode_recv {
    declare local var.input STRING;
    declare local var.decoded STRING;

    set var.input = "aGVsbG8=0";

    set var.decoded = digest.base64_decode(var.input);
    assert.equal(std.strlen(var.decoded), 5);
    assert.equal(var.decoded, "hello");

    set var.decoded = digest.base64url_decode(var.input);
    assert.equal(std.strlen(var.decoded), 5);
    assert.equal(var.decoded, "hello");

    set var.decoded = digest.base64url_nopad_decode(var.input);
    assert.equal(std.strlen(var.decoded), 6);
    assert.equal(var.decoded, "hello4");
}

// @scope: recv
// @suite: Test base64 decode NULL string
sub test_base64_decode_recv {
    declare local var.input STRING;
    declare local var.decoded STRING;

    set var.input = "c29tZSBkYXRhIHdpdGggACBhbmQg77u/";

    set var.decoded = digest.base64_decode(var.input);
    assert.equal(std.strlen(var.decoded), 15);
    assert.equal(var.decoded, "some data with ");

    set var.decoded = digest.base64url_decode(var.input);
    assert.equal(std.strlen(var.decoded), 15);
    assert.equal(var.decoded, "some data with ");

    set var.decoded = digest.base64url_nopad_decode(var.input);
    assert.equal(std.strlen(var.decoded), 15);
    assert.equal(var.decoded, "some data with ");
}

// @scope: recv
// @suite: Test base64 decode BOM string
sub test_base64_decode_recv {
  // Skip tests because we suspects Fastly has a tiny bug in base64 decoding with BOM 
    declare local var.input STRING;
    declare local var.decoded STRING;

    set var.input = "c29tZSBkYXRhIHdpdGgg77u/IGFuZCAA";

    // set var.decoded = digest.base64_decode(var.input);
    // assert.equal(std.strlen(var.decoded), 23);
    # assert.equal(var.decoded, "some data with \xef\xbb\xbf and");

    // set var.decoded = digest.base64url_decode(var.input);
    // assert.equal(std.strlen(var.decoded), 22);
    # assert.equal(var.decoded, "some data with ﻈ[�");

    // set var.decoded = digest.base64url_nopad_decode(var.input);
    // assert.equal(std.strlen(var.decoded), 22);
    # assert.equal(var.decoded, "some data with ﻈ[�");
}

