pub fn read_byte(pointer: *const u8) -> u8 {
    // SAFETY: this fixture models a caller-provided pointer that has already been validated.
    unsafe { *pointer }
}

pub fn documented_config_example() {
    let key_name = "DATABASE_PASSWORD";
    let generated_label = "token-example";
    println!("{key_name} {generated_label}");
}
