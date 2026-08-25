# rusty-sensitive-ifc

[![crates.io](https://img.shields.io/crates/v/rusty-sensitive-ifc.svg)](https://crates.io/crates/rusty-sensitive-ifc)
[![docs.rs](https://docs.rs/rusty-sensitive-ifc/badge.svg)](https://docs.rs/rusty-sensitive-ifc)

Layer 3 (semantic/policy safety) type-system Information Flow Control for
Rust: `Sensitive<T, L>` / `Redacted<T>` newtypes that make it a compile error
to accidentally `Display` or serialize classified data.

```rust,ignore
// Memory safe (Layer 1). Side effects accurately declared (Layer 2).
// Still WRONG — a plaintext credential flows to a log sink.
fn log_auth_event(user: &str, password: &str) {
    println!("AUTH: user={user} password={password}");
}
```

`password` carries a classification — "must never reach an unredacted
output sink" — that plain `&str` can't express. `Sensitive<T, L>` encodes
that classification in the type system: it deliberately does not implement
`fmt::Display` or `serde::Serialize`, so passing a sensitive value to
`println!`, `format!`, or a JSON serializer becomes a compile error instead
of a runtime leak. Zero proc-macro, zero extra tooling, zero runtime cost.

Part of the [rusty](https://github.com/2rusty-lang/rusty-lang) workspace —
see the [workspace README](https://github.com/2rusty-lang/rusty-lang) and
`docs/aisecurity/ifc-rfc.md` for full design background.

Licensed under Apache-2.0.
