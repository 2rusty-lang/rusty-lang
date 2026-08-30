#!/usr/bin/env rust-script
//! Renders an HTML slide deck to PDF (via weasyprint) and rasterizes every
//! page to PNG (via pdftoppm), at a given DPI.
//!
//! Usage:
//!   rust-script devscripts/render_slides.rs <input.html> <output.pdf> <png_out_dir> [dpi]
//!
//! Requires `weasyprint` and `pdftoppm` (poppler-utils) on PATH.

use std::env;
use std::fs;
use std::process::Command;

fn run(cmd: &mut Command) {
    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("failed to spawn {cmd:?}: {e}");
        std::process::exit(1);
    });
    if !status.success() {
        eprintln!("command failed: {cmd:?}");
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: {} <input.html> <output.pdf> <png_out_dir> [dpi=96]",
            args[0]
        );
        std::process::exit(1);
    }
    let input_html = &args[1];
    let output_pdf = &args[2];
    let png_out_dir = &args[3];
    let dpi = args.get(4).map(String::as_str).unwrap_or("96");

    fs::create_dir_all(png_out_dir).expect("create png_out_dir");

    println!("→ weasyprint {input_html} -> {output_pdf}");
    run(Command::new("weasyprint").args([input_html, output_pdf]));

    let png_prefix = format!("{}/slide", png_out_dir.trim_end_matches('/'));
    println!("→ pdftoppm {output_pdf} -> {png_prefix}-NN.png @ {dpi} dpi");
    run(Command::new("pdftoppm").args([
        "-png",
        "-r",
        dpi,
        output_pdf,
        &png_prefix,
    ]));

    let count = fs::read_dir(png_out_dir)
        .expect("read png_out_dir")
        .filter(|e| {
            e.as_ref()
                .map(|e| e.path().extension().and_then(|x| x.to_str()) == Some("png"))
                .unwrap_or(false)
        })
        .count();
    println!("done: {count} page(s) rendered to {png_out_dir}");
}
