# devscripts

Reproducible pipeline behind the "Why Rust's Allocator API Has Been Nightly
for a Decade" content campaign (blog post, slide deck, two narrated video
reels). Every script is a standalone `rust-script` — no `cargo build`, no
project of its own — and each shells out to a real CLI tool rather than
reimplementing PDF rendering, TTS, or video muxing in Rust.

## Prerequisites

- [`rust-script`](https://rust-script.org) (already on PATH in this
  environment; `cargo install rust-script` otherwise)
- [`weasyprint`](https://weasyprint.org) — HTML → PDF (`pipx install
  weasyprint` or `pip install --user weasyprint`)
- `pdftoppm` (poppler-utils) — PDF → PNG rasterization
- `ffmpeg` / `ffprobe` — video segment rendering and concatenation
- [`piper-tts`](https://github.com/OHF-Voice/piper1-gpl) — offline neural
  TTS: `pip install --user piper-tts`
- A Piper voice model (`.onnx` + `.onnx.json`), not committed here (~60 MB).
  This campaign used `en_US-lessac-medium`:
  ```sh
  BASE="https://huggingface.co/rhasspy/piper-voices/resolve/main/en/en_US/lessac/medium"
  curl -sL -o en_US-lessac-medium.onnx "$BASE/en_US-lessac-medium.onnx"
  curl -sL -o en_US-lessac-medium.onnx.json "$BASE/en_US-lessac-medium.onnx.json"
  ```
  Narration text never leaves the machine — synthesis is fully local once
  the voice model is downloaded.

## Scripts

Run all three from the repo root (`rusty/`).

### `render_slides.rs` — HTML slide deck → PDF → PNG pages

```sh
rust-script devscripts/render_slides.rs <input.html> <output.pdf> <png_out_dir> [dpi=96]
```

Used twice: once for the 16:9 presentation deck
(`assets/slides.html`), once for the 1080×1920 vertical reel deck
(`assets/reel-slides.html`).

### `synthesize_narration.rs` — narration text → WAV

```sh
rust-script devscripts/synthesize_narration.rs <narration_dir> <voice.onnx> <audio_out_dir> [length_scale=1.05]
```

Runs Piper once per `.txt` file in `narration_dir`, writing a same-named
`.wav` into `audio_out_dir`. `length_scale` > 1.0 slows the voice down
slightly (1.05 reads as natural/unhurried rather than rushed).

### `build_reels.rs` — slide PNGs + narration WAVs → final MP4 reels

```sh
rust-script devscripts/build_reels.rs <png_dir> <audio_dir> <segments_dir> <output_dir>
```

The `REELS` constant at the top of the script maps each reel to an ordered
list of `(narration key, slide number)` pairs — edit it there if the
segment count or order changes. Each `(image, audio)` pair becomes one
still-image MP4 segment with a quarter-second fade in/out, sized to the
audio's exact duration; segments are then concatenated (re-encoded, not
stream-copied, to avoid non-monotonic-DTS artifacts) into one H.264/AAC,
1080×1920, `+faststart` MP4 per reel.

## Full pipeline, end to end

```sh
cd /home/claudev/apps/rusty
VOICE=/path/to/en_US-lessac-medium.onnx

rust-script devscripts/render_slides.rs \
  devscripts/assets/slides.html \
  devscripts/output/rusty-capability-security-slides.pdf \
  devscripts/output/slides-png 100

rust-script devscripts/render_slides.rs \
  devscripts/assets/reel-slides.html \
  devscripts/output/reel-slides.pdf \
  devscripts/output/reel-slides-png 96

rust-script devscripts/synthesize_narration.rs \
  devscripts/assets/narration "$VOICE" devscripts/output/audio 1.05

rust-script devscripts/build_reels.rs \
  devscripts/output/reel-slides-png devscripts/output/audio \
  devscripts/output/segments devscripts/output
```

## Layout

```
devscripts/
  assets/
    slides.html          16:9 presentation deck (11 slides)
    reel-slides.html      1080x1920 reel deck (12 slides, 2 reels x 6)
    narration/*.txt        per-segment narration script (r1s1..r1s6, r2s1..r2s6)
  render_slides.rs
  synthesize_narration.rs
  build_reels.rs
  output/                 generated — safe to delete and re-run the pipeline
    rusty-capability-security-slides.pdf   the downloadable deck (also copied
                                            into wwwsite/public/downloads/)
    reel-1-why-rust-nightly.mp4            ~52s, 1080x1920
    reel-2-orthogonal-fix.mp4              ~50s, 1080x1920
    PUBLISHING-CHECKLIST.md                per-platform captions + asset map
```

`output/` is fully regenerable from `assets/` — nothing under it needs to be
hand-edited.
