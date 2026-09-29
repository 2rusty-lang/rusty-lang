// Positive case (RFC 0008): a mod-level ceiling covers every function
// inside it that has no explicit #[capability(...)] of its own — no
// per-function declaration needed for either, and the ceiling's permitted
// `network` doesn't get exercised as a real socket (see `net` stub below,
// matched purely by path segment the same way the real inspector matches
// `std::net::TcpStream`), just to keep this a real, deterministic UI test.

use capability_attr::capability;

mod net {
    pub fn send(_msg: &str) {}
}

#[capability(alloc(heap), io(network: yes, filesystem: no, display: no, process: no, any: no), ptr(none))]
mod handlers {
    pub fn get_user(id: u64) -> String {
        let msg = format!("GET /users/{id}");
        crate::net::send(&msg);
        msg
    }

    pub fn list_orders(user: u64) -> Vec<String> {
        vec![format!("GET /users/{user}/orders")]
    }
}

fn main() {
    assert_eq!(handlers::get_user(1), "GET /users/1");
    assert_eq!(handlers::list_orders(1), vec!["GET /users/1/orders"]);
}
