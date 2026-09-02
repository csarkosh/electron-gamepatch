"""The real consumer path: the `electron` npm package's own install.js, pointed at a local mirror of dist/.

Proves that what publish would upload satisfies @electron/get — asset name, SHASUMS256.txt
format, the two .npmrc keys — before any release exists. Requires `npm` and network for the
(binary-less) package tarball. `unittest discover` runs this module before test_pipeline
(alphabetical), so on a cold dist/ this builds the pinned Electron itself rather than skipping —
a skip here would let the gate pass without ever exercising the consumer contract.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).parent))
import gamepatch  # noqa: E402
from mirror import Mirror  # noqa: E402

PIN = os.environ.get("GAMEPATCH_PIN", "44.1.1")
DIST = ROOT / "dist"
FRAMEWORK = "Electron.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"
# Per platform: the build platform, the (ELECTRON_INSTALL_PLATFORM, ELECTRON_INSTALL_ARCH) the
# `electron` package names it by, and the patched binary inside the extracted dist/.
DARWIN = ("darwin-arm64", "darwin", "arm64", FRAMEWORK)
WIN32 = ("win32-x64", "win32", "x64", "electron.exe")


class Consumer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for platform, _, _, _ in (DARWIN, WIN32):
            if not (DIST / f"electron-v{PIN}-{platform}.zip").exists():
                DIST.mkdir(parents=True, exist_ok=True)
                gamepatch.build(PIN, platform, ROOT / "patches", ROOT / "cache", ROOT / "work", DIST)
        (DIST / "SHASUMS256.txt").write_text(gamepatch.shasums(DIST))
        cls.project = Path(tempfile.mkdtemp(prefix="consumer-"))
        subprocess.run(["npm", "init", "-y"], cwd=cls.project, check=True, capture_output=True)
        # The package without its binary; install.js is then run by hand against our mirror.
        subprocess.run(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", f"electron@{PIN}"],
                       cwd=cls.project, check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.project, ignore_errors=True)

    def run_install(self, mirror_url: str, target=DARWIN) -> subprocess.CompletedProcess:
        _, install_platform, install_arch, _ = target
        env = dict(os.environ,
                   npm_config_electron_mirror=mirror_url,          # what .npmrc `electron_mirror=` becomes
                   npm_config_electron_use_remote_checksums="1",   # what .npmrc `electron_use_remote_checksums=1` becomes
                   electron_config_cache=str(self.project / "cache"),
                   ELECTRON_INSTALL_PLATFORM=install_platform, ELECTRON_INSTALL_ARCH=install_arch)
        env.pop("ELECTRON_SKIP_BINARY_DOWNLOAD", None)
        shutil.rmtree(self.project / "node_modules/electron/dist", ignore_errors=True)
        return subprocess.run(["node", "install.js"], cwd=self.project / "node_modules/electron",
                              env=env, text=True, capture_output=True)

    def assert_installs_our_bytes(self, target) -> None:
        platform, _, _, binary = target
        with Mirror(DIST, PIN) as m:
            result = self.run_install(m.url, target)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        installed = self.project / "node_modules/electron/dist" / binary
        patched = ROOT / "work" / platform / "patched" / binary
        self.assertEqual(gamepatch.sha256_file(installed), gamepatch.sha256_file(patched))

    def test_installs_our_bytes_through_the_documented_config(self):
        self.assert_installs_our_bytes(DARWIN)

    def test_installs_our_win32_bytes_through_the_documented_config(self):
        """Spec 1.6 for the second patched platform: a win32-x64 consumer (the platform the
        install is *for*, resolved by ELECTRON_INSTALL_PLATFORM/ARCH, not the host) must get our
        patched electron.exe. The darwin case alone would pass even if win32-x64 shipped stock."""
        self.assert_installs_our_bytes(WIN32)

    def test_checksum_mismatch_is_refused(self):
        """Proves the remote-checksum path is live: a wrong SHASUMS256.txt must fail the install, not be ignored."""
        with Mirror(DIST, PIN) as m:
            m.corrupt_shasums(PIN)
            result = self.run_install(m.url)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.project / "node_modules/electron/dist" / FRAMEWORK).exists())


if __name__ == "__main__":
    unittest.main()
