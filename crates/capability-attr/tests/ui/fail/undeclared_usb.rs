// Negative case: body touches a USB device, but the function declared
// io(none) — must be a real compile_error!, not a silent pass, same as
// the original five categories' own undeclared_*.rs fixtures.

use capability_attr::capability;

mod rusb {
    pub struct Context;
    impl Context {
        pub fn new() -> Self {
            Self
        }
    }
}

#[capability(alloc(none), io(none), ptr(none))]
fn open_device() -> rusb::Context {
    rusb::Context::new()
}

fn main() {
    let _ = open_device();
}
