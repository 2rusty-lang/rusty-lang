// Positive case: the tainted value passes through a #[taint_sanitizer]
// before reaching the sink — compiles clean, no compile_error!.

use taint_check_macros::taint_check;

#[taint_check(labels = [password])]
mod auth {
    pub fn handle_login(#[sensitive(password)] password: &str) {
        let clean = redact(password);
        log_debug(&clean);
    }

    #[taint_sanitizer]
    fn redact(_s: &str) -> String {
        "[REDACTED]".to_string()
    }

    #[taint_sink(password, policy = "no_sensitive")]
    fn log_debug(msg: &str) {
        println!("{msg}");
    }
}

fn main() {
    auth::handle_login("hunter2");
}
