pub fn active(flag_a: bool, flag_b: bool, flag_c: bool, flag_d: bool, flag_e: bool, flag_f: bool) -> bool {
    if flag_a {
        if flag_b {
            if flag_c {
                if flag_d {
                    if flag_e {
                        if flag_f {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

fn foo() {
    let bar = 1;
    println!("{bar}");
}
