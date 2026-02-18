---
name: record-demo
description: Record a demo GIF from a VHS tape with automatic redaction of sensitive values via OCR
user-invocable: true
argument-hint: "<tape-file-or-description>"
---

# record-demo

Record a demo GIF using VHS with automatic OCR-based redaction of sensitive values.

## Prerequisites

- `~/go/bin/vhs` (v0.10.0+)
- `ffmpeg` / `ffprobe`
- `tesseract` (OCR engine)
- `convert` (ImageMagick)
- `make build` must succeed
- `.redact-patterns` file at project root (gitignored — optional, see format below; falls back to built-in AWS credential patterns)

## Steps

### Step 1 — Resolve input

- If the argument is a path to an existing `.tape` file, use it directly.
- If the argument is a text description, generate a new `.tape` file in `demo/` using the conventions below.

#### VHS Tape Generation Conventions

When generating a tape from a description, use these defaults:

```
# <Description of what the demo shows>
Output demo/<descriptive-name>.gif

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 600
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms
Set PlaybackSpeed 1

Env PATH "/home/tim/sca-cli:/snap/bin:/usr/local/bin:/usr/bin:/bin"

# Clean prompt
Hide
Type `export PS1="$ "`
Enter
Type "clear"
Enter
Show

Sleep 500ms
```

- Always start with the hidden PS1 setup block shown above.
- Use `Hide`/`Show` to skip loading delays (API calls, command processing). After an `Enter` that triggers an API call, insert `Hide`, then `Sleep 12s` (generous wait to ensure the call completes), then `Show`. This makes the demo snappy and avoids blank screen waiting.
- Use `Sleep` generously after `Enter` for short waits (1-3s for local output).
- Add viewing pauses (2-5s) after important output appears.
- See existing tapes in `demo/` for examples.

### Step 2 — Authenticate if needed

Run `./grant status` to check authentication state. If not authenticated, invoke the `/grant-login` skill first.

### Step 3 — Build the binary

Run `make build` to ensure `./grant` is current.

### Step 4 — Run VHS

1. Execute: `~/go/bin/vhs <tape-file>`
2. Parse the `Output` directive from the tape file to determine the output GIF path.
3. Verify the GIF was created.

### Step 5 — Detect sensitive regions

1. Use `ffprobe` to get GIF duration, frame rate, and frame count:
   ```bash
   ffprobe -v error -select_streams v:0 -show_entries stream=r_frame_rate,nb_read_frames,duration -count_frames -of json <gif>
   ```

2. Extract frames densely — every 10th frame (i.e., ~1 per second at 25fps) for thorough coverage:
   ```bash
   ffmpeg -i <gif> -vf "select='not(mod(n\,10))'" -vsync vfr /tmp/demo-frames/frame_%04d.png
   ```
   Dense extraction catches text that only appears briefly or during transitions.

3. For each frame, run OCR with bounding-box output:
   ```bash
   tesseract <frame.png> - tsv
   ```

4. **Load redaction patterns** from `.redact-patterns` at the project root. If the file is missing, fall back to these built-in defaults (safe to commit — they contain no proprietary names):
   ```
   value     AWS_ACCESS_KEY_ID
   value     AWS_SECRET_ACCESS_KEY
   value     AWS_SESSION_TOKEN
   prefix    ASIA
   prefix    AKIA
   ```
   Log a note that `.redact-patterns` was not found and only built-in AWS patterns are active.

5. Search OCR results against loaded patterns.

6. **Visually inspect extracted frames** — OCR may miss text on highlighted/colored backgrounds (e.g., survey prompt selection highlights in inverse video). Always open a few frames with the `Read` tool to spot sensitive text that tesseract missed, and manually add blur regions for those.

7. Collect bounding boxes: `(x, y, w, h, frame_number)` for each match.

8. Merge overlapping or adjacent boxes in the same region.

9. Compute time ranges from frame numbers: `start = frame_num / fps`.

10. **For `value` patterns**: size the blur width to cover only the actual text width of the value, NOT all the way to the right edge of the GIF. Extending blur to the right edge causes color tint artifacts in GIF palette quantization.

#### `.redact-patterns` File Format

A gitignored file at the project root. Each non-empty, non-comment line defines one redaction rule:

```
# Lines starting with # are comments
# Format: <mode> <pattern>
#
# Modes:
#   word     — blur the matched word's bounding box (case-insensitive OCR match)
#   value    — blur everything to the RIGHT of the match (from delimiter to edge of frame)
#              used for key=value or label: value lines
#   prefix   — blur any word starting with this prefix (4+ trailing chars)

word      CompanyName
value     AWS_ACCESS_KEY_ID
value     AWS_SECRET_ACCESS_KEY
value     AWS_SESSION_TOKEN
value     Session ID:
prefix    ASIA
prefix    AKIA
```

- **`word`**: Case-insensitive whole-word match. Blurs just the word's bounding box.
- **`value`**: Finds the label in OCR output, then blurs from the delimiter (`=` or `:`) to the right edge of the GIF. For `AWS_SESSION_TOKEN`, also blur continuation lines below until the next `export` or blank line.
- **`prefix`**: Blurs any OCR word that starts with this prefix and has 4+ additional characters (catches credential strings like `ASIA...`, `AKIA...`).

The user populates this file with their actual sensitive words. Since it's gitignored, the words never appear in the repo.

### Step 6 — Apply blur overlays

Use the `crop` + `boxblur` + `overlay` approach. Write filter graphs to temp files and use `-filter_complex_script` to avoid shell escaping issues.

#### Filter chain pattern

Each blur region N (1-indexed) follows this chain pattern:

```
[0]crop=W:H:X:Y,boxblur=R:P[b1]; [0][b1]overlay=X:Y:enable='between(t,S,E)'[v1]
[0]crop=W:H:X:Y,boxblur=R:P[b2]; [v1][b2]overlay=X:Y:enable='between(t,S,E)'[v2]
...
[0]crop=W:H:X:Y,boxblur=R:P[bN]; [v(N-1)][bN]overlay=X:Y:enable='between(t,S,E)'[vN]
```

Note: The first overlay uses `[0]` (not `[v0]`) as its base. Each subsequent overlay chains from the previous `[vN-1]`.

#### Boxblur radius constraints

The chroma plane radius must not exceed `min(crop_w, crop_h) / 4`. Choose parameters based on region height:

| Region height | Boxblur params | Notes |
|---------------|----------------|-------|
| h <= 22 | `boxblur=6:3:5:3` | Separate luma/chroma radii to satisfy chroma constraint |
| 22 < h <= 26 | `boxblur=6:3` | Safe for small regions |
| 26 < h <= 50 | `boxblur=10:3` | Medium regions |
| h > 50 | `boxblur=20:3` | Large regions |

For credential values that need stronger redaction, increase the iterations (power): e.g., `boxblur=6:5` instead of `boxblur=6:3`.

#### Two-pass GIF encoding

Write filter graphs to temp files, then run two-pass encoding:

```bash
# Pass 1 filter: append palettegen to the last blur output
# Write to /tmp/<name>_pass1.txt:
<blur_chain...>
[vN]palettegen=stats_mode=diff[pal]

ffmpeg -y -i <input> -filter_complex_script /tmp/<name>_pass1.txt -map "[pal]" /tmp/<name>_palette.png

# Pass 2 filter: append paletteuse
# Write to /tmp/<name>_pass2.txt:
<blur_chain...>
[vN][1:v]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle[out]

ffmpeg -y -i <input> -i /tmp/<name>_palette.png -filter_complex_script /tmp/<name>_pass2.txt -map "[out]" <output>
```

Overwrite the original GIF with the redacted output.

### Step 7 — Verify

1. Check file size — warn if > 5MB.
2. Extract a frame from a redacted region and display it using the `Read` tool so the user can visually confirm redaction.
3. Report to the user:
   - Output path
   - File size
   - Duration
   - Number and type of detected sensitive regions
   - Any warnings (large file, undetected expected patterns)

## Troubleshooting

- If tesseract misses text, try adjusting the `--psm` mode, or visually inspect frames for text on colored/highlighted backgrounds that OCR cannot read.
- If blur boxes are misaligned, check ffprobe frame dimensions vs actual GIF dimensions.
- For long `AWS_SESSION_TOKEN` values that wrap lines, check multiple OCR lines after the label match.
- If VHS fails, check that `~/go/bin/vhs` is on PATH and the tape syntax is valid.
- Use `tesseract <frame.png> - tsv` manually on a single frame to debug OCR accuracy.

### Known Issues

- **GIF palette quantization color tint**: Blurred regions can pick up a green/teal color tint from the terminal theme during GIF palette quantization. Mitigate by:
  1. Narrowing blur width to cover only the actual text (not extending to frame edge).
  2. Increasing boxblur iterations (e.g., `boxblur=6:5` instead of `boxblur=6:3`).
  3. As a last resort, using `drawbox` filled with the terminal background color (e.g., `0x1e1e2e` for Catppuccin Mocha) instead of blur. However, blur is preferred for redaction aesthetics.
- **OCR misses highlighted text**: Tesseract struggles with text rendered on inverse-video or colored highlight backgrounds (e.g., the currently-selected item in a survey prompt). Always visually inspect frames from interactive prompts and add manual blur regions for any missed sensitive text.
