//! `BodyInspector` — a `syn::visit::Visit` walker that detects actual
//! capability usage (allocation calls, I/O macros/paths, raw-pointer
//! writes) inside a function body, per Phase 1 of
//! `docs/aisecurity/capability-rfc-updated.md`.
//!
//! This is AST-level detection, not data-flow analysis: it recognizes
//! syntactic patterns (a call whose path ends in `Vec::new`, a `println!`
//! macro invocation, a raw-pointer deref on the left of an assignment) —
//! the same scope the RFC's own Phase 1 sketch describes. It cannot see
//! through indirection (a function pointer, a trait object call, a macro
//! that itself expands to an allocating call) — that is explicitly Phase
//! 2/3 territory (cross-function capability flow), not this pass's scope.

use path_match::{path_has_segment, path_last_two, path_to_string};
use syn::visit::Visit;
use syn::{Block, Expr, ExprAssign, ExprCall, ExprUnary, Macro, UnOp};

use crate::parser::{AllocLevel, CapabilitySet, IoLevel, PtrBound, PtrLevel};

/// Walks a function body and accumulates the maximum capability level
/// observed per category.
pub struct BodyInspector {
    detected: CapabilitySet,
}

impl BodyInspector {
    fn note_alloc(&mut self, level: AllocLevel) {
        self.detected.merge_max(&CapabilitySet {
            alloc: Some(level),
            io: None,
            ptr: None,
        });
    }

    fn note_io(&mut self, level: IoLevel) {
        self.detected.merge_max(&CapabilitySet {
            alloc: None,
            io: Some(level),
            ptr: None,
        });
    }

    fn note_ptr(&mut self, level: PtrLevel) {
        self.detected.merge_max(&CapabilitySet {
            alloc: None,
            io: None,
            ptr: Some(level),
        });
    }
}

/// A call path is allocating if its last one or two segments match a known
/// heap-allocating constructor. Matching on the trailing segments (rather
/// than requiring a fully-qualified path) intentionally catches both
/// `Vec::new(...)` and `std::vec::Vec::new(...)` forms.
const ALLOCATING_CALL_SUFFIXES: &[&str] = &[
    "Vec::new",
    "Vec::with_capacity",
    "Box::new",
    "String::new",
    "String::from",
    "HashMap::new",
    "BTreeMap::new",
    "VecDeque::new",
    "Arc::new",
    "Rc::new",
];

/// Path segments (anywhere in the call path) that indicate filesystem I/O.
const FILESYSTEM_PATH_MARKERS: &[&str] = &["fs"];
/// Path segments that indicate network I/O.
const NETWORK_PATH_MARKERS: &[&str] = &["net", "TcpStream", "TcpListener", "reqwest"];
/// Path segments that indicate subprocess spawning.
const PROCESS_PATH_MARKERS: &[&str] = &["Command"];
/// Fully-qualified raw-pointer write helper suffixes.
const PTR_WRITE_CALL_SUFFIXES: &[&str] =
    &["ptr::write", "ptr::write_volatile", "ptr::write_unaligned"];
/// Fully-qualified raw-pointer read helper suffixes.
const PTR_READ_CALL_SUFFIXES: &[&str] = &["ptr::read", "ptr::read_volatile", "ptr::read_unaligned"];

impl<'ast> Visit<'ast> for BodyInspector {
    fn visit_macro(&mut self, mac: &'ast Macro) {
        let name = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();

        match name.as_str() {
            "println" | "eprintln" | "print" | "eprint" | "write" | "writeln" => {
                self.note_io(IoLevel::Display);
            }
            "vec" => self.note_alloc(AllocLevel::Heap),
            _ => {}
        }

        syn::visit::visit_macro(self, mac);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(p) = call.func.as_ref() {
            let full = path_to_string(&p.path);
            let last_two = path_last_two(&p.path);

            if ALLOCATING_CALL_SUFFIXES.iter().any(|s| last_two == *s) {
                self.note_alloc(AllocLevel::Heap);
            }
            if FILESYSTEM_PATH_MARKERS
                .iter()
                .any(|m| path_has_segment(&p.path, m))
            {
                self.note_io(IoLevel::Filesystem);
            }
            if NETWORK_PATH_MARKERS
                .iter()
                .any(|m| path_has_segment(&p.path, m))
            {
                self.note_io(IoLevel::Network);
            }
            if PROCESS_PATH_MARKERS
                .iter()
                .any(|m| path_has_segment(&p.path, m))
            {
                self.note_io(IoLevel::Process);
            }
            if PTR_WRITE_CALL_SUFFIXES.iter().any(|s| full.ends_with(s)) {
                // Phase 1 has no address-range verification (that is the
                // RFC's PAC-integration addon, out of scope here) — any
                // detected raw write is conservatively classified `Any`,
                // never `Bounded`. See parser.rs's `PtrBound` doc comment.
                self.note_ptr(PtrLevel::Write(PtrBound::Any));
            }
            if PTR_READ_CALL_SUFFIXES.iter().any(|s| full.ends_with(s)) {
                self.note_ptr(PtrLevel::Read);
            }
        }

        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_assign(&mut self, assign: &'ast ExprAssign) {
        if let Expr::Unary(ExprUnary {
            op: UnOp::Deref(_), ..
        }) = assign.left.as_ref()
        {
            // `*ptr = value;` — a raw-pointer write. Conservatively `Any`
            // for the same reason as the `ptr::write(...)` call case above.
            self.note_ptr(PtrLevel::Write(PtrBound::Any));
        }
        syn::visit::visit_expr_assign(self, assign);
    }

    fn visit_expr_unary(&mut self, unary: &'ast ExprUnary) {
        if matches!(unary.op, UnOp::Deref(_)) {
            // A bare `*ptr` read outside of assignment position. Assignment
            // LHS derefs are handled (as writes) in `visit_expr_assign`
            // above; this only fires for read-position derefs.
            self.note_ptr(PtrLevel::Read);
        }
        syn::visit::visit_expr_unary(self, unary);
    }
}

/// Run [`BodyInspector`] over a function body and return the accumulated
/// [`CapabilitySet`].
pub fn inspect_body(block: &Block) -> CapabilitySet {
    let mut inspector = BodyInspector {
        detected: CapabilitySet::default(),
    };
    syn::visit::visit_block(&mut inspector, block);
    inspector.detected
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    fn detect(src: &str) -> CapabilitySet {
        let block: Block = syn::parse_str(&format!("{{ {src} }}")).unwrap();
        inspect_body(&block)
    }

    #[test]
    fn detects_vec_new_as_heap_alloc() {
        let caps = detect("let _v: Vec<u8> = Vec::new();");
        assert_eq!(caps.alloc_or_none(), AllocLevel::Heap);
        assert_eq!(caps.io_or_none(), IoLevel::None);
    }

    #[test]
    fn detects_box_new_as_heap_alloc() {
        let caps = detect("let _b = Box::new(5);");
        assert_eq!(caps.alloc_or_none(), AllocLevel::Heap);
    }

    #[test]
    fn detects_println_as_display_io() {
        let caps = detect(r#"println!("hi");"#);
        assert_eq!(caps.io_or_none(), IoLevel::Display);
        assert_eq!(caps.alloc_or_none(), AllocLevel::None);
    }

    #[test]
    fn detects_vec_macro_as_heap_alloc() {
        let caps = detect("let _v = vec![1, 2, 3];");
        assert_eq!(caps.alloc_or_none(), AllocLevel::Heap);
    }

    #[test]
    fn detects_std_fs_as_filesystem_io() {
        let caps = detect(r#"let _ = std::fs::read_to_string("x");"#);
        assert_eq!(caps.io_or_none(), IoLevel::Filesystem);
    }

    #[test]
    fn detects_command_new_as_process_io() {
        let caps = detect(r#"let _ = std::process::Command::new("ls");"#);
        assert_eq!(caps.io_or_none(), IoLevel::Process);
    }

    #[test]
    fn detects_tcpstream_as_network_io() {
        let caps = detect(r#"let _ = std::net::TcpStream::connect("x:1");"#);
        assert_eq!(caps.io_or_none(), IoLevel::Network);
    }

    #[test]
    fn detects_raw_pointer_write_via_deref_assign() {
        let caps = detect("unsafe { *(p as *mut u32) = 1; }");
        assert_eq!(caps.ptr_or_none(), PtrLevel::Write(PtrBound::Any));
    }

    #[test]
    fn detects_raw_pointer_write_via_ptr_write_call() {
        let caps = detect("unsafe { core::ptr::write(p, 1u32); }");
        assert_eq!(caps.ptr_or_none(), PtrLevel::Write(PtrBound::Any));
    }

    #[test]
    fn detects_raw_pointer_read() {
        let caps = detect("let _v = unsafe { *p };");
        assert_eq!(caps.ptr_or_none(), PtrLevel::Read);
    }

    #[test]
    fn clean_body_detects_nothing() {
        let block: Block = parse_quote! {{
            let x = 1;
            let y = x + 1;
            y
        }};
        let caps = inspect_body(&block);
        assert_eq!(caps.alloc_or_none(), AllocLevel::None);
        assert_eq!(caps.io_or_none(), IoLevel::None);
        assert_eq!(caps.ptr_or_none(), PtrLevel::None);
    }

    #[test]
    fn accumulates_the_maximum_across_multiple_operations() {
        let caps = detect(
            r#"
            let _v: Vec<u8> = Vec::new();
            println!("{}", _v.len());
            let _ = std::process::Command::new("ls");
            "#,
        );
        assert_eq!(caps.alloc_or_none(), AllocLevel::Heap);
        // Process (4) outranks Display (1) — merge_max keeps the higher risk.
        assert_eq!(caps.io_or_none(), IoLevel::Process);
    }
}
