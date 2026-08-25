// Negative case: body performs a raw-pointer write, but the function
// declared `ptr(none)` — must be a real compile_error!.

use capability_attr::capability;

#[capability(alloc(none), io(none), ptr(none))]
unsafe fn write_raw(p: *mut u32, val: u32) {
    unsafe {
        *p = val;
    }
}

fn main() {
    let mut x: u32 = 0;
    unsafe { write_raw(&mut x as *mut u32, 42) };
}
