// Negative case: a #[sensitive] parameter passed straight into a
// #[taint_sink] call — the RFC's "direct" flow case. Must be a real
// compile_error!, not a silent pass.

use taint_check_macros::taint_check;

#[taint_check(labels = [password])]
mod auth {
    pub fn handle_login(#[sensitive(password)] password: &str) {
        log_debug(password);
    }

    #[taint_sink(password, policy = "no_sensitive")]
    fn log_debug(msg: &str) {
        println!("{msg}");
    }
}

fn main() {
    auth::handle_login("hunter2");
}
