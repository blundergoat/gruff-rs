pub fn test_named_helper_without_attribute() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}

#[test]
#[ignore = "documented flaky clock on CI"]
fn ignored_with_reason() {
    assert_eq!(2, 1 + 1);
}

#[test]
fn meaningful_assertion() {
    let actual = 2 + 2;
    assert_eq!(actual, 4);
}
