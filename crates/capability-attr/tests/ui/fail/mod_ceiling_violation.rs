// Negative case (RFC 0008): the mod's ceiling permits `network` but not
// `filesystem` — a function with no explicit #[capability(...)] of its
// own that touches the filesystem must be a real compile_error!, not a
// silent pass just because it's covered by *some* ceiling.

use capability_attr::capability;

#[capability(alloc(none), io(network: yes, filesystem: no, display: no, process: no, any: no), ptr(none))]
mod handlers {
    pub fn export_receipt(order: &str) {
        std::fs::write("receipt.txt", order).unwrap();
    }
}

fn main() {
    handlers::export_receipt("total: 42");
}
