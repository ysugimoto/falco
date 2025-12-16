// @scope: recv
// @suite: Test regex match
sub test_regex_recv {
    declare local var.input STRING;
    declare local var.group1 STRING;
    set var.input = "abc";
    if (var.input ~ "^(\w+)$") {
        set var.group1 = re.group.1;
    }
    assert.equal(re.group.1, "abc");
    // will be reset re.group.N when matched
    if (var.input ~ ".*") {
        set var.group1 = re.group.1;
    }
    assert.is_notset(re.group.1);
}

// @scope: recv
// @suite: Test regex match without reset groups
sub test_regex_no_reset_recv {
    declare local var.input STRING;
    declare local var.group1 STRING;
    set var.input = "abc";
    if (var.input ~ "^(\w+)$") {
        set var.group1 = re.group.1;
    }
    assert.equal(re.group.1, "abc");
    // will not be reset re.group.N when not matched
    if (var.input ~ "xyz*") {
        set var.group1 = re.group.1;
    }
    assert.equal(re.group.1, "abc");
}

// @scope: recv
// @suite: Test anchor patterns
sub test_anchors_recv {
    declare local var.url STRING;

    // PCRE behavior: ^$ does NOT match empty string (unlike Go regexp)
    set var.url = "";
    assert.false(var.url ~ "^$", "^$ should NOT match empty string in PCRE");

    // Test ^abc prefix match
    set var.url = "abc";
    assert.true(var.url ~ "^abc", "^abc should match 'abc'");
    assert.equal(re.group.0, "abc");

    set var.url = "abcxyz";
    assert.true(var.url ~ "^abc", "^abc should match prefix of 'abcxyz'");
    assert.equal(re.group.0, "abc");

    // Test abc$ suffix match
    set var.url = "abc";
    assert.true(var.url ~ "abc$", "abc$ should match 'abc'");

    set var.url = "xyzabc";
    assert.true(var.url ~ "abc$", "abc$ should match suffix of 'xyzabc'");

    // Test ^abc$ exact match
    set var.url = "abc";
    assert.true(var.url ~ "^abc$", "^abc$ should exactly match 'abc'");

    set var.url = "xyzabc";
    assert.false(var.url ~ "^abc$", "^abc$ should not match 'xyzabc'");
}

// @scope: recv
// @suite: Test multiple capture groups
sub test_multiple_captures_recv {
    declare local var.host STRING;

    // Test URL path segments
    set var.host = "/products/uk/123";
    if (var.host ~ "/products/(uk|us|au)/(\d+)") {
        assert.equal(re.group.0, "/products/uk/123");
        assert.equal(re.group.1, "uk");
        assert.equal(re.group.2, "123");
    }

    // Test domain parsing
    set var.host = "www.example.com";
    if (var.host ~ "^([^.]+)\.([^.]+)\.([^.]+)$") {
        assert.equal(re.group.1, "www");
        assert.equal(re.group.2, "example");
        assert.equal(re.group.3, "com");
    }
}

// @scope: recv
// @suite: Test case insensitive matching
sub test_case_insensitive_recv {
    declare local var.ua STRING;

    set var.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0";
    assert.true(var.ua ~ "(?i)chrome", "Case insensitive should match 'Chrome'");

    set var.ua = "MOZILLA FIREFOX";
    assert.true(var.ua ~ "(?i)mozilla", "Case insensitive should match 'MOZILLA'");
}

// @scope: recv
// @suite: Test special character classes
sub test_character_classes_recv {
    declare local var.input STRING;

    // Digit class
    set var.input = "abc123";
    assert.true(var.input ~ "\d+", "Should match digits");
    if (var.input ~ "(\d+)") {
        assert.equal(re.group.1, "123");
    }

    // Word class
    set var.input = "hello_world";
    assert.true(var.input ~ "\w+", "Should match word characters");

    // Whitespace
    set var.input = "hello world";
    assert.true(var.input ~ "\s", "Should match whitespace");

    // Non-digit
    set var.input = "abc";
    assert.true(var.input ~ "\D+", "Should match non-digits");
}

// @scope: recv
// @suite: Test quantifiers
sub test_quantifiers_recv {
    declare local var.input STRING;

    // Zero or more
    set var.input = "aaa";
    assert.true(var.input ~ "a*", "a* should match 'aaa'");

    // One or more
    assert.true(var.input ~ "a+", "a+ should match 'aaa'");

    // Zero or one
    set var.input = "a";
    assert.true(var.input ~ "a?", "a? should match 'a'");

    // Exact count
    set var.input = "aaa";
    assert.true(var.input ~ "a{3}", "a{3} should match 'aaa'");

    // Range count
    set var.input = "aa";
    assert.true(var.input ~ "a{2,4}", "a{2,4} should match 'aa'");

    // Minimum count
    set var.input = "aaaa";
    assert.true(var.input ~ "a{2,}", "a{2,} should match 'aaaa'");
}

// @scope: recv
// @suite: Test URL patterns
sub test_url_patterns_recv {
    declare local var.url STRING;

    // Path with extension
    set var.url = "/path/file.html";
    assert.true(var.url ~ "\.html$", "Should match .html extension");

    // Query string detection
    set var.url = "/path?foo=bar";
    assert.true(var.url ~ "\?", "Should match query string");

    // Admin path
    set var.url = "/admin/users";
    assert.true(var.url ~ "^/admin(/.*)?$", "Should match admin path");

    // File extension alternatives
    set var.url = "/image.jpg";
    assert.true(var.url ~ "\.(jpg|png|gif)$", "Should match image extension");

    // Versioned API
    set var.url = "/api/v1/users";
    assert.true(var.url ~ "^/api/v\d+/", "Should match versioned API");
}

// @scope: recv
// @suite: Test escape sequences
sub test_escapes_recv {
    declare local var.input STRING;

    // Literal dot
    set var.input = "file.txt";
    assert.true(var.input ~ "file\.txt", "Should match literal dot");

    // Literal question mark
    set var.input = "what?";
    assert.true(var.input ~ "what\?", "Should match literal ?");

    // Literal plus
    set var.input = "1+1";
    assert.true(var.input ~ "1\+1", "Should match literal +");

    // Literal parenthesis
    set var.input = "(test)";
    assert.true(var.input ~ "\(test\)", "Should match literal parentheses");
}

// @scope: recv
// @suite: Test regsub function
sub test_regsub_recv {
    declare local var.result STRING;

    // Remove www prefix
    set var.result = regsub("www.example.com", "www\.", "");
    assert.equal(var.result, "example.com");

    // URL path rewrite
    set var.result = regsub("/old/path/file.html", "^/old/(.*)", "/new/\1");
    assert.equal(var.result, "/new/path/file.html");

    // Backreference with digits
    set var.result = regsub("foo123bar", "foo(\d+)", "found: [\1]");
    assert.equal(var.result, "found: [123]bar");

    // Multiple backreferences
    set var.result = regsub("John Doe", "^(\w+)\s+(\w+)$", "\2, \1");
    assert.equal(var.result, "Doe, John");

    // Replace first occurrence only
    set var.result = regsub("aaaa", "a", "b");
    assert.equal(var.result, "baaa");

    // No match returns original
    set var.result = regsub("hello", "xyz", "abc");
    assert.equal(var.result, "hello");
}

// @scope: recv
// @suite: Test regsuball function
sub test_regsuball_recv {
    declare local var.result STRING;

    // Normalize slashes
    set var.result = regsuball("//foo///bar//baz", "/+", "/");
    assert.equal(var.result, "/foo/bar/baz");

    // Replace all occurrences
    set var.result = regsuball("aaaa", "a", "b");
    assert.equal(var.result, "bbbb");

    // Normalize whitespace
    set var.result = regsuball("hello    world   test", "\s+", " ");
    assert.equal(var.result, "hello world test");

    // Remove all digits
    set var.result = regsuball("abc123def456ghi", "\d+", "");
    assert.equal(var.result, "abcdefghi");

    // Replace special characters
    set var.result = regsuball("hello@world!test#foo", "[@!#]", "-");
    assert.equal(var.result, "hello-world-test-foo");

    // Clean alphanumeric
    set var.result = regsuball("test-123_abc!@#", "[^a-zA-Z0-9]", "");
    assert.equal(var.result, "test123abc");
}

// @scope: recv
// @suite: Test alternation patterns
sub test_alternation_recv {
    declare local var.ua STRING;

    // Browser detection
    set var.ua = "Chrome";
    if (var.ua ~ "(Chrome|Firefox|Safari)") {
        assert.equal(re.group.1, "Chrome");
    }

    set var.ua = "Firefox";
    if (var.ua ~ "(Chrome|Firefox|Safari)") {
        assert.equal(re.group.1, "Firefox");
    }

    set var.ua = "Edge";
    assert.false(var.ua ~ "(Chrome|Firefox|Safari)", "Edge should not match");
}

// @scope: recv
// @suite: Test negation operator
sub test_negation_recv {
    declare local var.url STRING;

    set var.url = "/path/file.txt";
    assert.true(var.url !~ "\.js$", "Should not match .js files");

    set var.url = "/path/file.js";
    assert.false(var.url !~ "\.js$", "Should match .js files");
}

// @scope: recv
// @suite: Test nested capture groups
sub test_nested_groups_recv {
    declare local var.input STRING;

    set var.input = "dummy";
    if (var.input ~ "((.*))") {
        assert.equal(re.group.0, "dummy");
        assert.equal(re.group.1, "dummy");
        assert.equal(re.group.2, "dummy");
    }
}

// @scope: recv
// @suite: Test optional groups
sub test_optional_groups_recv {
    declare local var.input STRING;

    set var.input = "foo";
    if (var.input ~ "^([^;]*)(;.*)?$") {
        assert.equal(re.group.0, "foo");
        assert.equal(re.group.1, "foo");
        // Optional group is captured as empty string, not notset
        assert.equal(re.group.2, "");
    }

    set var.input = "foo;bar";
    if (var.input ~ "^([^;]*)(;.*)?$") {
        assert.equal(re.group.0, "foo;bar");
        assert.equal(re.group.1, "foo");
        assert.equal(re.group.2, ";bar");
    }
}

// @scope: recv
// @suite: Test word boundaries
sub test_word_boundaries_recv {
    declare local var.input STRING;

    set var.input = "test testing tested";
    if (var.input ~ "\btest\b") {
        assert.equal(re.group.0, "test");
    }

    // Should match word boundary, not substring
    set var.input = "testing";
    assert.false(var.input ~ "\btest\b", "Should not match 'test' in 'testing'");
}

// @scope: recv
// @suite: Test PCRE empty string behavior
sub test_pcre_empty_string_recv {
    declare local var.input STRING;

    // PCRE does NOT match empty strings with ^$
    set var.input = "";
    assert.false(var.input ~ "^$", "PCRE: empty string should NOT match ^$");

    // PCRE does NOT match empty strings with ^(.*)$
    assert.false(var.input ~ "^(.*)$", "PCRE: empty string should NOT match ^(.*)$");

    // But non-empty strings work fine
    set var.input = "test";
    assert.true(var.input ~ "^(.*)$", "Non-empty strings match ^(.*)$");
}
