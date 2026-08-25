// Real compile-fail proof: `Sensitive<T, L>` deliberately does not
// implement `fmt::Display`, so passing it to `println!("{}", ...)` (which
// desugars to a `Display` bound) is a compile error, not a runtime leak.
// See packages/sensitive-ifc/src/lib.rs's crate-level docs for why this is
// the actual enforcement mechanism, not just documentation.

use sensitive_ifc::{Credential, Sensitive};

fn main() {
    let secret: Sensitive<String, Credential> = Sensitive::new("hunter2".to_string());
    println!("{}", secret);
}
