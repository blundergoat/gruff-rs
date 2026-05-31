use super::*;

pub(crate) fn cases() -> Vec<CalibrationCase> {
    vec![
        // ----- architecture -----
        case(
            "architecture.large-module",
            Box::new(|root| baseline_with_lib(root, &module_with_n_items(28))),
            Box::new(|root| baseline_with_lib(root, &module_with_n_items(3))),
        ),
        case(
            "architecture.module-fan-out",
            Box::new(|root| baseline_with_lib(root, &module_with_n_mod_decls(10))),
            Box::new(|root| baseline_with_lib(root, &module_with_n_mod_decls(2))),
        ),
        case(
            "architecture.public-api-surface",
            Box::new(|root| baseline_with_lib(root, &module_with_n_items(15))),
            Box::new(|root| baseline_with_lib(root, &module_with_n_items(3))),
        ),
        // ----- complexity -----
        case(
            "complexity.cognitive",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn complex(items: &[i32], flag_a: bool, flag_b: bool, flag_c: bool) -> i32 {
    let mut total = 0;
    for value in items {
        if flag_a {
            if flag_b {
                if flag_c {
                    if *value > 0 {
                        total += value;
                    } else if *value < 0 {
                        total -= value;
                    }
                }
            }
        }
        if flag_a && flag_b {
            total += 1;
        } else if flag_b || flag_c {
            total -= 1;
        }
    }
    total
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn simple(value: i32) -> i32 {
    value + 1
}
"#,
                )
            }),
        ),
        case(
            "complexity.cyclomatic",
            Box::new(|root| {
                let mut body = String::from("/// Probe.\npub fn many_branches(value: i32) -> i32 {\n    let mut total = 0;\n");
                for index in 0..15 {
                    body.push_str(&format!(
                        "    if value == {index} {{ total += {index}; }}\n"
                    ));
                }
                body.push_str("    total\n}\n");
                baseline_with_lib(root, &body);
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\npub fn straight_line(value: i32) -> i32 { value + 1 }\n",
                )
            }),
        ),
        case(
            "complexity.nesting-depth",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn deeply_nested(flag_a: bool, flag_b: bool, flag_c: bool, flag_d: bool, flag_e: bool) -> i32 {
    if flag_a {
        if flag_b {
            if flag_c {
                if flag_d {
                    if flag_e {
                        return 1;
                    }
                }
            }
        }
    }
    0
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub fn shallow(flag_a: bool, flag_b: bool) -> i32 {
    if flag_a && flag_b {
        return 1;
    }
    0
}
"#,
                )
            }),
        ),
        // ----- concurrency -----
        case(
            "concurrency.blocking-call-in-async",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub async fn blocks() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn synchronous() { std::thread::sleep(std::time::Duration::from_millis(1)); }\n",
                    )
            }),
        ),
        case(
            "concurrency.lock-across-await",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub async fn holds(lock: &std::sync::Mutex<i32>) {
    let guard = lock.lock().unwrap();
    other().await;
    println!("{}", *guard);
}

async fn other() {}
"#,
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    r#"/// Probe.
pub async fn drops_first(lock: &std::sync::Mutex<i32>) {
    let guard = lock.lock().unwrap();
    drop(guard);
    other().await;
}

async fn other() {}
"#,
                )
            }),
        ),
        case(
            "concurrency.unbounded-channel",
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn make_channel() { let (_tx, _rx) = std::sync::mpsc::channel::<i32>(); }\n",
                    )
            }),
            Box::new(|root| {
                baseline_with_lib(
                        root,
                        "/// Probe.\npub fn make_channel() { let (_tx, _rx) = std::sync::mpsc::sync_channel::<i32>(16); }\n",
                    )
            }),
        ),
        // ----- dead code -----
        case(
            "dead-code.unused-private-function",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\nfn never_called() {}\npub fn entry() {}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\nfn helper() {}\npub fn entry() { helper(); }\n",
                )
            }),
        ),
        case(
            "dead-code.unused-private-item-candidate",
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\nfn unused_isolated_widget() {}\npub fn entry() {}\n",
                )
            }),
            Box::new(|root| {
                baseline_with_lib(
                    root,
                    "/// Probe.\nfn helper_widget() {}\npub fn entry() { helper_widget(); }\n",
                )
            }),
        ),
        // ----- dependency -----
        case(
            "dependency.duplicate-locked-version",
            Box::new(|root| {
                calibration_baseline(root);
                fs::write(
                    root.join("Cargo.lock"),
                    r#"# generated
version = 3

[[package]]
name = "calibration-fixture"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"

[[package]]
name = "serde"
version = "1.0.1"

[[package]]
name = "serde"
version = "1.0.2"
"#,
                )
                .expect("dup lock");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "dependency.git-source",
            Box::new(|root| {
                calibration_baseline(root);
                fs::write(
                    root.join("Cargo.toml"),
                    r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "git source fixture"
license = "MIT"

[dependencies]
serde = { git = "https://example.test/serde" }
"#,
                )
                .expect("git manifest");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "dependency.missing-package-metadata",
            Box::new(|root| {
                fs::create_dir_all(root.join("src")).expect("src dir");
                fs::write(root.join("README.md"), "# Calibration\n").expect("readme");
                fs::write(
                    root.join("Cargo.toml"),
                    r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
"#,
                )
                .expect("bare manifest");
                fs::write(root.join("Cargo.lock"), CALIBRATION_BASELINE_LOCKFILE)
                    .expect("lockfile");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "dependency.path-source",
            Box::new(|root| {
                calibration_baseline(root);
                fs::write(
                    root.join("Cargo.toml"),
                    r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "path source fixture"
license = "MIT"

[dependencies]
helper = { path = "../helper" }
"#,
                )
                .expect("path manifest");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
        case(
            "dependency.wildcard-version",
            Box::new(|root| {
                calibration_baseline(root);
                fs::write(
                    root.join("Cargo.toml"),
                    r#"[package]
name = "calibration-fixture"
version = "0.1.0"
edition = "2021"
description = "wildcard fixture"
license = "MIT"

[dependencies]
serde = "*"
"#,
                )
                .expect("wildcard manifest");
                write_lib(root, "/// Probe.\npub fn entry() {}\n");
            }),
            Box::new(|root| baseline_with_lib(root, "/// Probe.\npub fn entry() {}\n")),
        ),
    ]
}
