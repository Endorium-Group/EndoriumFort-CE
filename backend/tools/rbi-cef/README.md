# RBI CEF-OSR helper (`endoriumfort-rbi-cef`)

The real "tiles" engine helper for Remote Browser Isolation: renders a URL with
Chromium Embedded Framework in **offscreen (windowless)** mode, encodes only the
**dirty rectangles** CEF reports as JPEG tiles, and streams them over the
EndoriumFort tile protocol (see `main.cc`). It is a drop-in replacement for the
synthetic `endoriumfort_rbi_stub` — same wire protocol — so the backend relay and
the frontend canvas are unchanged.

## Enabling it at runtime
The backend picks the engine via env:

```
ENDORIUMFORT_RBI_ENGINE=tiles
ENDORIUMFORT_RBI_HELPER=/app/bin/endoriumfort-rbi-cef
ENDORIUMFORT_RBI_MAX_FPS=20         # CEF windowless_frame_rate
ENDORIUMFORT_RBI_JPEG_QUALITY=55    # per-tile JPEG quality
```

Leaving `ENDORIUMFORT_RBI_ENGINE` unset (or `cdp`) keeps the built-in
Chromium/CDP MJPEG path.

## Building
Needs a CEF binary distribution (minimal is enough) and a **C++20** compiler
(recent CEF headers use `std::same_as`/`std::derived_from`). libjpeg is optional:
with it, tiles are JPEG (format 0); without it, the helper streams raw-RGBA tiles
(format 2), which the frontend also renders. Download CEF from
https://cef-builds.spotifycdn.com/index.html (pin a version), extract, then:

```
cmake -S backend/tools/rbi-cef -B build-rbi-cef -DCEF_ROOT=/opt/cef
cmake --build build-rbi-cef -j
```

Validated against **CEF 154.0.32 (chromium 154)**; `main.cc` compiles clean
against its headers. Pin a version you trust via the `CEF_VERSION` build-arg.

The build copies the CEF runtime files (`libcef.so`, `*.pak`, `icudtl.dat`,
`locales/`, `v8_context_snapshot.bin`, `chrome-sandbox`, …) next to the binary.
The helper only runs with those files present in its directory.

In Docker this is done by the `rbi-cef` build stage; the production image bundles
the helper + CEF runtime under `/app/bin/` and sets the env above.

## Headless / GPU tuning (env, browser process)
- `ENDORIUMFORT_RBI_OZONE` — Ozone platform (default **`headless`**, required in
  containers; without it CEF aborts with "Missing X server or $DISPLAY"). Set
  `x11` when a display is available, `off` to omit.
- `ENDORIUMFORT_RBI_ANGLE` — ANGLE GL backend for GPU-less hosts (default
  `swiftshader`; `off` to omit). The helper always sets
  `--disable-gpu --disable-gpu-compositing --enable-begin-frame-scheduling`.
- `ENDORIUMFORT_RBI_CEF_FLAGS` — extra space-separated Chromium switches without
  the leading `--`.

## Link/runtime dependencies
libcef.so needs its DT_NEEDED libs present to link AND run. The build stage needs
`libx11-dev` (for `-lX11`) plus the runtime set; the runtime image needs the set:
`libasound2 libatk1.0-0 libatk-bridge2.0-0 libatspi2.0-0 libcairo2 libcups2
libdbus-1-3 libexpat1 libgbm1 libglib2.0-0 libnss3 libnspr4 libpango-1.0-0
libudev1 libx11-6 libxcb1 libxcomposite1 libxdamage1 libxext6 libxfixes3
libxkbcommon0 libxrandr2` (see the Dockerfile `rbi-cef` stages).

## Validation status (2026-10-05)
Built AND run in a **clean Debian trixie container** against CEF 154 via the exact
Dockerfile dependency path: the helper **renders offscreen headless and emits
valid JPEG tiles** (verified: SURFACE 500x350 + TILE fmt=0 with JPEG magic FF D8),
**clean exit (code 0)**. The dbus "Failed to connect to the bus" lines are benign
(no system bus in the container). A `stack smashing` seen earlier was only the
WSL/WSLg **x11** path; the default headless Ozone path exits cleanly.

## File transfer + clipboard paste
The helper also carries files in/out of the isolated page and pastes text:
- **Upload** (hôte → cible): a `U <id> <x> <y> <pathB64> <nameB64>` line drops a
  local file at (x,y) via `CefDragData`; a `F <seq> <pathsB64CSV|->` line completes
  a file-picker the page opened (intercepted in `CefDialogHandler::OnFileDialog`,
  surfaced to the client as a type-4 stdout frame). This covers both drag-drop
  uploaders and `<input type=file>` buttons (e.g. the ESXi datastore uploader).
- **Download** (cible → hôte): `CefDownloadHandler` stages the file under
  `<cache>/downloads/` and streams it back as type 5/6/7 frames.
- **Paste** (hôte → distant): a `P <textB64>` line injects the text as CHAR key
  events.

File transfer requires the **tiles** engine, so run the backend with
`ENDORIUMFORT_RBI_ENGINE=tiles` (the CEF image's recommended setting). Size caps:
`ENDORIUMFORT_RBI_MAX_UPLOAD_MB` (backend, 0=unlimited). The EE `rbi.transfer`
license feature adds a DLP policy (allow/deny per direction, size/extension
limits) + audit via `ENDORIUMFORT_RBI_ALLOW_{UPLOAD,DOWNLOAD,PASTE}`,
`ENDORIUMFORT_RBI_MAX_TRANSFER_MB`, `ENDORIUMFORT_RBI_BLOCKED_EXTENSIONS`.

⚠️ Two CEF overrides drift across releases — verify against the pinned headers on
a version bump: `CefDialogHandler::OnFileDialog` (its `accept_extensions` /
`accept_descriptions` params and the dropped selected-filter index) and
`CefDownloadHandler::OnBeforeDownload` (its void-vs-bool return type).

## Notes / TODO
- Encoding is JPEG per tile (libjpeg). WebP (format 1) can be added later for
  smaller tiles.
- A file dialog completes with a single file (v1); multi-select picks the first.
- Key input maps JS `keyCode` → `windows_key_code`; `char` events carry the
  BMP code unit. Extended/IME input can be refined later.
- `no_sandbox` is set (headless container; the whole helper process is the
  isolation boundary). To keep the CEF sandbox, ship `chrome-sandbox` setuid and
  drop that flag.
