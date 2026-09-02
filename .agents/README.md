# How this repository works

**Product.** GitHub releases whose tag and asset names mirror upstream Electron, where the
`darwin-arm64` zip (so far) has small byte patches applied and every other platform zip is
upstream's, untouched. Consumers point `electron_mirror` at us and set
`electron_use_remote_checksums=1`. That contract is in `docs/design.md` and must not change.

**Pipeline.** `.github/workflows/release.yml`:
1. `plan` — `tools/release_plan.py` compares upstream stable tags with ours and picks
   versions (latest on the highest major; or everything newer than our newest on it).
2. `build` (macos-14) — the `gate` composite action: unit tests → `gamepatch.py build` →
   `verify.py` → integration suite (`tests/integration/`: pinned pipeline properties — including
   the zip layout matching upstream entry-by-entry, `(type+mode, name)` pairs from `zipinfo`,
   not names alone — plus the consumer contract through the real `electron` installer against a
   local mirror) → the behavioural probe, blocking, with the stock build as a control. Artifacts:
   `dist/electron-v<ver>-darwin-arm64.zip` + `.patches.json`.
3. `publish` (ubuntu) — `gamepatch.py passthrough` adds upstream's other zips, `shasums`
   writes `SHASUMS256.txt`, `notes` writes the release body, `gh release create`.

`ci.yml` runs the same `gate` action on every push and PR against the pinned version in
`tests/integration/test_pipeline.py`. A change that breaks the engine, the release layout or
the behaviour is caught there, before it can reach a release.

**Engine.** `tools/gamepatch.py`. Pure functions on top (parsing `.sym`, applying sites,
validating `patch.json`, SHASUMS formatting) with unit tests in `tests/`; IO below
(download + upstream checksum verification, `unzip`/`zip` — never Python's `zipfile` for
`Electron.app`, it drops symlinks — Mach-O checks, `codesign`: only the binaries a patch
modified are re-signed, ad hoc, on a scratch copy outside the bundle — never `--deep`).

**Why symbols, not pattern scans.** Each release's `-symbols.zip` contains a Breakpad `.sym`
with a `FUNC <addr> <size> <paramsize> <name>` line per function. `__TEXT` sits at vmaddr 0
and fileoff 0 in Electron Framework, so the address *is* the file offset. The engine asserts
both facts (`MODULE` id == binary UUID + "0"; `otool -l` shows `__TEXT` at 0).

**Failure mode by design.** A wrong `expect` means the compiler changed the function;
the build fails, nothing is published. Re-derive by hand (see new-patch.md step 4).

**Local loop.**
```sh
python3 -m unittest discover -s tests -v
python3 tools/gamepatch.py build --version 44.1.1 --platform darwin-arm64   # ~2 min, 260 MB cache
python3 tools/verify.py   --version 44.1.1 --platform darwin-arm64
python3 -m unittest discover -s tests/integration -v                        # builds again if needed; needs npm + network
test/probe/run.sh work/darwin-arm64/patched/Electron.app                    # needs a display, steals focus 15 s
```
`work/`, `dist/`, `cache/` are git-ignored.

**History.** The first patch came out of a spike in the `fps` game repo
(`docs/research/2026-08-25-pointer-lock-cooldown.md` there); the numbers in
`patches/pointerlock-noeject/README.md` are from it.
