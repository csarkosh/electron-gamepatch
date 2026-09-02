"""Serve a dist/ directory the way a GitHub release does: <base>/v<version>/<asset>."""
from __future__ import annotations

import functools
import http.server
import shutil
import tempfile
import threading
from pathlib import Path


class Mirror:
    def __init__(self, dist: Path, version: str):
        self.root = Path(tempfile.mkdtemp(prefix="mirror-"))
        rel = self.root / f"v{version}"
        rel.mkdir()
        for p in dist.iterdir():
            if p.suffix == ".zip" or p.name == "SHASUMS256.txt":
                shutil.copy2(p, rel / p.name)
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(self.root))
        handler.log_message = lambda *a, **k: None  # type: ignore[attr-defined]
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/"

    def corrupt_shasums(self, version: str) -> None:
        p = self.root / f"v{version}" / "SHASUMS256.txt"
        p.write_text(p.read_text().replace("0", "1", 1))

    def __exit__(self, *exc):
        self.server.shutdown()
        shutil.rmtree(self.root, ignore_errors=True)
