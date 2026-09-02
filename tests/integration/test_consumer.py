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
PLATFORM = "darwin-arm64"
DIST = ROOT / "dist"
FRAMEWORK = "Electron.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"


class Consumer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (DIST / f"electron-v{PIN}-{PLATFORM}.zip").exists():
            DIST.mkdir(parents=True, exist_ok=True)
            gamepatch.build(PIN, PLATFORM, ROOT / "patches", ROOT / "cache", ROOT / "work", DIST)
        (DIST / "SHASUMS256.txt").write_text(gamepatch.shasums(DIST))
        cls.project = Path(tempfile.mkdtemp(prefix="consumer-"))
        subprocess.run(["npm", "init", "-y"], cwd=cls.project, check=True, capture_output=True)
        # The package without its binary; install.js is then run by hand against our mirror.
        subprocess.run(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", f"electron@{PIN}"],
                       cwd=cls.project, check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.project, ignore_errors=True)

    def run_install(self, mirror_url: str) -> subprocess.CompletedProcess:
        env = dict(os.environ,
                   npm_config_electron_mirror=mirror_url,          # what .npmrc `electron_mirror=` becomes
                   npm_config_electron_use_remote_checksums="1",   # what .npmrc `electron_use_remote_checksums=1` becomes
                   electron_config_cache=str(self.project / "cache"),
                   ELECTRON_INSTALL_PLATFORM="darwin", ELECTRON_INSTALL_ARCH="arm64")
        env.pop("ELECTRON_SKIP_BINARY_DOWNLOAD", None)
        shutil.rmtree(self.project / "node_modules/electron/dist", ignore_errors=True)
        return subprocess.run(["node", "install.js"], cwd=self.project / "node_modules/electron",
                              env=env, text=True, capture_output=True)

    def test_installs_our_bytes_through_the_documented_config(self):
        with Mirror(DIST, PIN) as m:
            result = self.run_install(m.url)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        installed = self.project / "node_modules/electron/dist" / FRAMEWORK
        patched = ROOT / "work" / PLATFORM / "patched" / FRAMEWORK
        self.assertEqual(gamepatch.sha256_file(installed), gamepatch.sha256_file(patched))

    def test_checksum_mismatch_is_refused(self):
        """Proves the remote-checksum path is live: a wrong SHASUMS256.txt must fail the install, not be ignored."""
        with Mirror(DIST, PIN) as m:
            m.corrupt_shasums(PIN)
            result = self.run_install(m.url)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.project / "node_modules/electron/dist" / FRAMEWORK).exists())


if __name__ == "__main__":
    unittest.main()
