// Negative case: body spawns a subprocess, but only `io(display)` was
// declared — `io(process)` exceeds it.

use capability_attr::capability;

#[capability(alloc(none), io(display), ptr(none))]
fn run_pager() {
    let _cmd = std::process::Command::new("less");
    println!("spawning pager");
}

fn main() {
    run_pager();
}
