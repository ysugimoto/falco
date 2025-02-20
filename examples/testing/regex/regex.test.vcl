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
    if (var.input ~ ".*") {
        set var.group1 = re.group.1;
    }
    assert.is_notset(re.group.1);
}
