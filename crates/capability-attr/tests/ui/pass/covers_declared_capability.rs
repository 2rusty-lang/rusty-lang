// Positive case: every operation in the body is within what was declared —
// compiles clean, no compile_error!.

use capability_attr::capability;

#[capability(alloc(heap), io(display), ptr(none))]
fn log_message(msg: &str) {
    let buf: Vec<u8> = msg.bytes().collect();
    println!("{}", buf.len());
}

#[capability(alloc(none), io(none), ptr(none))]
fn pure_computation(a: u32, b: u32) -> u32 {
    a + b
}

fn main() {
    log_message("hello");
    assert_eq!(pure_computation(2, 3), 5);
}
