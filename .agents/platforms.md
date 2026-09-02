# Platforms

| Platform | Status | Patched binary | Signing after patch |
|---|---|---|---|
| darwin-arm64 | patched | `Electron.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework` | sign only the patched binary, ad hoc, outside the bundle; never `--deep` (upstream is ad-hoc/linker-signed too). Consumers' `electron-builder` re-signs with their identity. |
| darwin-x64 | pass-through | same path, x86-64 code | as above |
| mas-* | pass-through | same path | as above (App Store builds are re-signed by the consumer anyway) |
| win32-x64 / win32-arm64 / win32-ia32 | pass-through | `electron.exe` and `*.dll` — which binary holds the function is read from the `-symbols.zip` (one `.sym` per module); unverified for Windows | none required to run; Authenticode is the consumer's job |
| linux-x64 / linux-arm64 / linux-armv7l | pass-through | `electron` ELF | none |

**Symbols.** Every platform has `electron-v<ver>-<platform>-symbols.zip` with Breakpad
`.sym` files per binary. The engine currently opens `<binary basename>.sym`; on Windows the
module name carries `.exe`/`.dll` (`electron.exe.sym`).

**Address ↔ file offset.** Only proven for the Mach-O framework (`__TEXT` at vmaddr 0, fileoff
0; the engine asserts it). PE and ELF need a section-table translation (RVA → file offset):
implement `assert_text_at_zero`'s equivalent per format before enabling a platform, and add
the format's disassembler (`llvm-objdump` handles all three on a Mac).

**Instruction encoding.** The pointer-lock cooldown constant `1250000` (0x1312D0) is a
`mov w9,#0x12d0; movk w9,#0x13,lsl#16` pair on arm64; on x86-64 expect a 32-bit immediate in
`cmp`/`add`/`lea`, so `expect` bytes and lengths differ per arch. The `HandleUserPressedEscape`
short-circuit is `xor eax,eax; ret` (`31c0c3`, 3 bytes) on x86-64 — the site length changes,
which is fine: `expect`/`write` only need to match each other.

**Runners.** `macos-14` (free on public repos) has `unzip`, `zip`, `codesign`, `dwarfdump`,
`otool`, `xcrun llvm-objdump`, `python3`. `ubuntu-latest` is used only for pass-through and
publishing. Windows binaries can be patched on any runner once the PE offset translation
exists; there is no signing step.
