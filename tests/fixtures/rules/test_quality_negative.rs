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

#[test]
fn mutated_binding_is_not_trivial() {
    let mut total = 1;
    total += 1;
    assert_eq!(total, 2);
}

#[test]
fn shadowed_binding_is_not_trivial() {
    let value = 1;
    let value = value + 9;
    assert_eq!(value, 10);
}

#[test]
fn derived_value_is_not_trivial() {
    let seed = 5;
    let doubled = seed * 2;
    assert_eq!(doubled, 10);
}
