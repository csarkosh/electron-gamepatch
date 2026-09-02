# pointerlock-noeject

**What it changes.** Chromium's browser process ejects a page's pointer lock when the user
presses Esc (`PointerLockController::HandleUserPressedEscape()` in
`chrome/browser/ui/exclusive_access/pointer_lock_controller.cc`) and then refuses to re-grant
it for 1.25 s (`kEffectiveUserEscapeDuration`). For a game that means every Esc — open a
menu, close it — is followed by a dead zone where clicking does nothing.

This patch makes `HandleUserPressedEscape()` return `false` without ejecting. Esc then falls
through to the page like any other key. The page releases the lock itself when it wants to
(`document.exitPointerLock()`), and a page-initiated release never arms the cooldown, so the
next `requestPointerLock()` is granted immediately.

**The bytes.** The function is 17 instructions; its prologue is replaced by `mov w0, #0; ret`.
Eight bytes, one site, located per release from Electron's published Breakpad symbols.

**Measured** (Electron 44.0.0, darwin-arm64, real Esc via `osascript`, 3 rounds each):
stock relocks after 1322–1526 ms; patched relocks in 10–24 ms with the page seeing
`keydown Escape` while still locked. In a real game (click → Esc → Resume): 12–16 ms.

**What a page must do.** Handle `keydown` for `Escape` while locked and call
`document.exitPointerLock()` if it wants the menu behaviour; otherwise Esc does nothing and
the lock stays. The only remaining way out of a lock the page never releases is defocusing
the window.

**Side effects.** Because `HandleUserPressedEscape()` now returns `false`, Esc also falls
through to the fullscreen controller: in an HTML-fullscreen window Esc still exits
fullscreen. Desktop shells should size the window themselves rather than use HTML fullscreen.

The ad-hoc re-signing this patch requires changes the framework's codesign identifier (from
`Electron Framework` to a hash-suffixed one) and drops the `linker-signed` flag; harmless for
consumers who re-sign with `electron-builder`, visible in `codesign -dvvv`.
