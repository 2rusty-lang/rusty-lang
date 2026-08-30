#!/usr/bin/env rust-script
//! Synthesizes one WAV file per .txt narration segment using Piper TTS,
//! fully offline (no text leaves the machine).
//!
//! Usage:
//!   rust-script devscripts/synthesize_narration.rs <narration_dir> <voice.onnx> <audio_out_dir> [length_scale=1.05]
//!
//! Requires `python3 -m piper` (pip install --user piper-tts) and a
//! downloaded Piper voice model (.onnx + .onnx.json).

use std::env;
use std::fs;
use std::process::{Command, Stdio};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: {} <narration_dir> <voice.onnx> <audio_out_dir> [length_scale=1.05]",
            args[0]
        );
        std::process::exit(1);
    }
    let narration_dir = &args[1];
    let voice = &args[2];
    let audio_out_dir = &args[3];
    let length_scale = args.get(4).map(String::as_str).unwrap_or("1.05");

    fs::create_dir_all(audio_out_dir).expect("create audio_out_dir");

    let mut entries: Vec<_> = fs::read_dir(narration_dir)
        .expect("read narration_dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("txt"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    if entries.is_empty() {
        eprintln!("no .txt files found in {narration_dir}");
        std::process::exit(1);
    }

    for entry in entries {
        let path = entry.path();
        let stem = path.file_stem().unwrap().to_string_lossy().to_string();
        let out_wav = format!("{}/{}.wav", audio_out_dir.trim_end_matches('/'), stem);
        let text = fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("failed to read {}: {e}", path.display());
            std::process::exit(1);
        });

        println!("→ synthesizing {stem} -> {out_wav}");
        let mut child = Command::new("python3")
            .args([
                "-m",
                "piper",
                "-m",
                voice,
                "--length-scale",
                length_scale,
                "-f",
                &out_wav,
            ])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                eprintln!("failed to spawn piper: {e}");
                std::process::exit(1);
            });

        {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(text.as_bytes())
                .expect("write narration text to piper stdin");
        }

        let status = child.wait().expect("wait for piper");
        if !status.success() {
            eprintln!("piper failed for {stem}");
            std::process::exit(1);
        }
    }

    println!("done: narration synthesized into {audio_out_dir}");
}
