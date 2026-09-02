# electron-gamepatch

Official Electron releases, republished with small binary patches that remove browser
behaviour hostile to games. Byte-identical to upstream except the documented patch sites
(and the ad-hoc code signature that re-signing them requires). Built on free GitHub
runners from Electron's own release artifacts — no Chromium checkout, no compile.

## Use it

Two lines in your project's `.npmrc`:

```ini
electron_mirror=https://github.com/csarkosh/electron-gamepatch/releases/download/
electron_use_remote_checksums=1
```

Then `npm install electron@<version>` as usual. `electron-builder`, `@electron/packager` and
everything else are unaffected — they see a normal Electron. The second line is required:
the `electron` package verifies downloads against a bundled checksum list by default and
would reject our bytes; with it set, it verifies against the `SHASUMS256.txt` in our release.

Every release tag mirrors upstream (`v44.1.1` republishes Electron `v44.1.1`), asset names
are identical, and every `electron-v<ver>-<platform>.zip` upstream publishes is present:
**patched where a patch exists, passed through byte-identical everywhere else**, so pointing
the mirror at us never breaks an install on a platform we have not patched yet. Other upstream
artifacts (`chromedriver-*`, `ffmpeg-*`, `mksnapshot-*`, headers, hunspell) are not mirrored;
tools that resolve them from `electron_mirror` must keep using upstream.

Re-cuts: when a platform becomes patched for an already-published version, its zip and
`SHASUMS256.txt` are replaced under the same tag and the release notes say so; verify with
remote checksums as documented.

## Patches

| Patch | Platforms | What it does |
|---|---|---|
| [pointerlock-noeject](patches/pointerlock-noeject/) | darwin-arm64, win32-x64 | Esc never ejects pointer lock; the page owns Esc and relocks instantly. |

## How it works

Electron publishes Breakpad symbols for every release. `tools/gamepatch.py` resolves each
patch's function by name in that release's `.sym`, asserts the expected original bytes, writes
the replacement, re-zips — and, on macOS, re-signs the modified binary; Windows binaries are
unsigned upstream and stay unsigned. `tools/verify.py` disassembles the result and proves the
binary differs from upstream only at the declared sites on every platform; on macOS it also
checks the signature of the shipped bytes and launches it, while for `win32-*` the launch
proof is a separate Windows CI leg (`test/probe/`), which measures the effect with a real
keypress. `.github/workflows/release.yml` does this daily for every new upstream release on
the tracked (latest stable) major.

A new Electron whose compiler output changes a patched function fails the byte assertion,
and nothing is published for that version until a human re-derives the bytes.

## Verify a release yourself

```sh
unzip -q electron-v44.1.1-darwin-arm64.zip -d ours && unzip -q <upstream zip> -d theirs
cmp -l "ours/Electron.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework" \
       "theirs/Electron.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework" | head
```
The differing bytes are: the eight bytes of the patch, the `LC_CODE_SIGNATURE` load command's
`datasize` field and the `__LINKEDIT` segment's `vmsize`/`filesize` fields in the header, and
the code-signature blob at the end of the file.

## Building from source instead

Every patch here could be a source patch on an Electron fork. That is the right tool when a
change cannot be expressed as a byte rewrite; it costs a ~30 GB Chromium checkout and a build.
See `docs/design.md` and `.agents/` for where the line is.

## License

MIT for this repository. The republished binaries carry Electron's and Chromium's own
licences, unchanged, inside every zip.
