#!/usr/bin/env rust-script
//! Assembles narrated vertical (1080x1920) video reels from slide PNGs +
//! matching narration WAVs, one ffmpeg-rendered segment per (image, audio)
//! pair, concatenated into final MP4s.
//!
//! Usage:
//!   rust-script devscripts/build_reels.rs <png_dir> <audio_dir> <segments_dir> <output_dir>
//!
//! `png_dir` must contain slide-01.png .. slide-NN.png (as produced by
//! render_slides.rs). `audio_dir` must contain <key>.wav files matching the
//! REELS table below. Requires `ffmpeg`/`ffprobe` on PATH.

use std::fs;
use std::process::Command;

// (reel output filename, [(narration key, 1-based slide number), ...])
const REELS: &[(&str, &[(&str, u32)])] = &[
    (
        "reel-1-why-rust-nightly.mp4",
        &[
            ("r1s1", 1),
            ("r1s2", 2),
            ("r1s3", 3),
            ("r1s4", 4),
            ("r1s5", 5),
            ("r1s6", 6),
        ],
    ),
    (
        "reel-2-orthogonal-fix.mp4",
        &[
            ("r2s1", 7),
            ("r2s2", 8),
            ("r2s3", 9),
            ("r2s4", 10),
            ("r2s5", 11),
            ("r2s6", 12),
        ],
    ),
];

fn run(cmd: &mut Command) {
    let output = cmd.output().unwrap_or_else(|e| {
        eprintln!("failed to spawn {cmd:?}: {e}");
        std::process::exit(1);
    });
    if !output.status.success() {
        eprintln!(
            "command failed: {cmd:?}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::process::exit(1);
    }
}

fn probe_duration(wav: &str) -> f64 {
    let output = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "csv=p=0",
            wav,
        ])
        .output()
        .expect("run ffprobe");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("parse duration")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "usage: {} <png_dir> <audio_dir> <segments_dir> <output_dir>",
            args[0]
        );
        std::process::exit(1);
    }
    let png_dir = args[1].trim_end_matches('/').to_string();
    let audio_dir = args[2].trim_end_matches('/').to_string();
    let segments_dir = args[3].trim_end_matches('/').to_string();
    let output_dir = args[4].trim_end_matches('/').to_string();

    fs::create_dir_all(&segments_dir).expect("create segments_dir");
    fs::create_dir_all(&output_dir).expect("create output_dir");

    for (reel_file, segments) in REELS {
        let mut segment_paths = Vec::new();

        for (key, slide_num) in *segments {
            let img = format!("{png_dir}/slide-{slide_num:02}.png");
            let wav = format!("{audio_dir}/{key}.wav");
            let seg_out = format!("{segments_dir}/{key}.mp4");

            let dur = probe_duration(&wav);
            let fade_out_start = (dur - 0.25).max(0.0);
            let vf = format!(
                "fade=t=in:st=0:d=0.25,fade=t=out:st={fade_out_start:.3}:d=0.25"
            );

            println!("→ rendering segment {key} ({dur:.2}s)");
            run(Command::new("ffmpeg").args([
                "-y",
                "-loop",
                "1",
                "-i",
                &img,
                "-i",
                &wav,
                "-c:v",
                "libx264",
                "-tune",
                "stillimage",
                "-pix_fmt",
                "yuv420p",
                "-c:a",
                "aac",
                "-b:a",
                "192k",
                "-shortest",
                "-vf",
                &vf,
                "-r",
                "30",
                &seg_out,
            ]));

            segment_paths.push(seg_out);
        }

        // ffmpeg's concat demuxer resolves relative paths in the list file
        // relative to the list file's own directory, not the process cwd —
        // so this must list bare filenames since segments live alongside it.
        let list_path = format!("{segments_dir}/{reel_file}.list.txt");
        let list_body: String = segment_paths
            .iter()
            .map(|p| {
                let name = std::path::Path::new(p)
                    .file_name()
                    .expect("segment path has a filename")
                    .to_string_lossy();
                format!("file '{name}'\n")
            })
            .collect();
        fs::write(&list_path, list_body).expect("write concat list");

        let final_out = format!("{output_dir}/{reel_file}");
        println!("→ concatenating -> {final_out}");
        run(Command::new("ffmpeg").args([
            "-y",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            &list_path,
            "-c:v",
            "libx264",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
            "-b:a",
            "192k",
            "-movflags",
            "+faststart",
            &final_out,
        ]));

        let dur = probe_duration(&final_out);
        println!("done: {final_out} ({dur:.1}s)");
    }
}
