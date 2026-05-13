pub fn ready(
    flag_a: bool,
    flag_b: bool,
    flag_c: bool,
    flag_d: bool,
    flag_e: bool,
    flag_f: bool,
) -> bool {
    let mut score = 0;
    if flag_a {
        score += 1;
        if flag_b {
            score += 1;
            if flag_c {
                score += 1;
                if flag_d {
                    score += 1;
                    if flag_e {
                        score += 1;
                        if flag_f {
                            score += 1;
                        }
                    }
                }
            }
        }
    }
    if flag_a && flag_b {
        score += 1;
    }
    if flag_a || flag_c {
        score += 1;
    }
    if flag_b && flag_d {
        score += 1;
    }
    if flag_c || flag_e {
        score += 1;
    }
    if flag_d && flag_f {
        score += 1;
    }
    if flag_e || flag_a {
        score += 1;
    }
    if flag_f && flag_b {
        score += 1;
    }
    if flag_a {
        score += 1;
    }
    if flag_b {
        score += 1;
    }
    if flag_c {
        score += 1;
    }
    if flag_d {
        score += 1;
    }
    if flag_e {
        score += 1;
    }
    if flag_f {
        score += 1;
    }

    score > 8
}
