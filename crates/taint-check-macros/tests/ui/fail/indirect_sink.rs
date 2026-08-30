// Negative case: rfcs/0003-taint-check.md's own guide-level example — a
// #[sensitive] value passed through one intermediate `let` (a method call
// on the tainted receiver) before reaching a #[taint_sink] call. Must be a
// real compile_error!, not a silent pass.

use taint_check_macros::taint_check;

#[taint_check(labels = [password])]
mod auth {
    pub fn handle_login(#[sensitive(password)] password: &str) {
        let echoed = password.to_string();
        log_debug(&echoed);
    }

    #[taint_sink(password, policy = "no_sensitive")]
    fn log_debug(msg: &str) {
        println!("{msg}");
    }
}

fn main() {
    auth::handle_login("hunter2");
}
