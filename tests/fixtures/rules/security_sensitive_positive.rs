pub fn read_byte(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

pub fn committed_secret_examples() {
    let env_secret = "DATABASE_PASSWORD=correct-horse-battery-123";
    let generated_token = "Q7m2P9x8R4s6T1v3W5y7Z0a2B4c6D8e0";
    println!("{env_secret} {generated_token}");
}
