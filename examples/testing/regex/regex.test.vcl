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
sub test_regex_recv {
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
