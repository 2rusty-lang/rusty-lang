// Negative case: body allocates on the heap via `Vec::new()`, but the
// function declared `alloc(none)` — must be a real compile_error!, not a
// silent pass.

use capability_attr::capability;

#[capability(alloc(none), io(none), ptr(none))]
fn quiet_fn() {
    let _buf: Vec<u8> = Vec::new();
}

fn main() {
    quiet_fn();
}
