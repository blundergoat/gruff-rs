pub fn is_active(flag_a: bool, flag_b: bool) -> bool {
    if flag_a && flag_b {
        return true;
    }

    false
}

fn calculate_total() {
    let subtotal = 1;
    let tax = 1;
    println!("{}", subtotal + tax);
}
