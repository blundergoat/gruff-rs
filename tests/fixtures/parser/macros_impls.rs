macro_rules! call_block {
    ($body:block) => {
        $body
    };
}

pub struct Harness {
    value: usize,
}

impl Harness {
    pub fn process(&self, a: bool, b: String, c: String, d: String, e: String, f: String) {
        call_block!({
            if a {
                println!("{}{}{}{}{}", b, c, d, e, f);
            }
        });
    }
}

#[test]
fn test_macro_fixture() {
    call_block!({
        let _value = 1;
    });
}
