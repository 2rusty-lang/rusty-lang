// Positive case: the widened io categories (registry/serial/usb/bluetooth)
// work at function level exactly like the original five, matched purely
// by path segment the same way std::net::TcpStream already is — this
// local `rusb` stub shadows the real crate's name on purpose, so the
// detector's marker match fires without a real USB dependency.

use capability_attr::capability;

mod rusb {
    pub struct Context;
    impl Context {
        pub fn new() -> Self {
            Self
        }
    }
}

#[capability(alloc(none), io(usb), ptr(none))]
fn open_device() -> rusb::Context {
    rusb::Context::new()
}

fn main() {
    let _ = open_device();
}
