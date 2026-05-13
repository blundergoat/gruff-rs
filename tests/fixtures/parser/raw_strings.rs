pub fn raw_string_has_unbalanced_delimiters() {
    let payload = r#"{"braces": "{ still data }", "paren": ")", "bracket": "]"}"#;
    println!("{payload}");
}
