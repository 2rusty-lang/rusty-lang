#!/usr/bin/env rust-script
//! Summarize a `stdev-tools test-coverage --json` report: total
//! covered/coverable/ratio, plus a per-file count of uncovered-region
//! proposals, sorted most-affected file first.
//!
//! ```cargo
//! [dependencies]
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! ```
//!
//! Usage:
//!   stdev-tools test-coverage . --json > /tmp/coverage.json
//!   rust-script devscripts/coverage_gap_summary.rs /tmp/coverage.json

use std::collections::HashMap;
use std::env;
use std::fs;

use serde::Deserialize;

#[derive(Deserialize)]
struct Report {
    covered: u64,
    coverable: u64,
    ratio: f64,
    proposals: Vec<Proposal>,
}

#[derive(Deserialize)]
struct Proposal {
    file: String,
}

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: coverage_gap_summary.rs <test-coverage-json-file>");
        std::process::exit(2);
    });
    let contents = fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("{path}: could not read file: {e}");
        std::process::exit(2);
    });
    let report: Report = serde_json::from_str(&contents).unwrap_or_else(|e| {
        eprintln!("{path}: not valid test-coverage JSON: {e}");
        std::process::exit(2);
    });

    println!(
        "covered {} coverable {} ratio {:.4}",
        report.covered, report.coverable, report.ratio
    );
    println!("proposals: {}", report.proposals.len());
    println!();

    let mut counts: HashMap<String, usize> = HashMap::new();
    for p in &report.proposals {
        *counts.entry(p.file.clone()).or_insert(0) += 1;
    }
    let mut counts: Vec<(String, usize)> = counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (file, n) in counts {
        println!("{n:4}  {file}");
    }
}
