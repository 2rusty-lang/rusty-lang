// Positive case (RFC 0008): a function inside a ceiling'd mod may still
// carry its own, narrower #[capability(...)] — it's checked against its
// own declaration, exactly as if there were no enclosing ceiling at all,
// and never against the mod's broader one.

use capability_attr::capability;

mod net {
    pub fn send(_msg: &str) {}
}

#[capability(alloc(none), io(network: yes, filesystem: no, display: no, process: no, any: no), ptr(none))]
mod handlers {
    // `use` at the crate root does not propagate into a nested `mod` —
    // each nested `fn`'s own #[capability(...)] needs it in scope here too.
    use capability_attr::capability;

    pub fn get_user(id: u64) {
        crate::net::send("GET /users");
        let _ = id;
    }

    // No I/O at all, unlike its siblings — kept as its own explicit,
    // precise declaration even though the mod's ceiling would also cover
    // an unannotated `fn` doing nothing.
    #[capability(alloc(none), io(none), ptr(none))]
    pub fn validate_id(id: u64) -> bool {
        id > 0
    }
}

fn main() {
    handlers::get_user(1);
    assert!(handlers::validate_id(1));
}
