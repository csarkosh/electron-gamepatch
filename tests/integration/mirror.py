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
        # Speak HTTP/1.1, as the real release CDN does. Under the default HTTP/1.0 the server
        # closes the socket after the body, and Node 22.23.1's bundled undici asserts
        # (assert(!this.paused) in Parser.finish) when that end arrives while the download is
        # paused for backpressure — install.js then dies before writing anything.
        handler.protocol_version = "HTTP/1.1"  # type: ignore[attr-defined]
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/"

    def corrupt_shasums(self, version: str) -> None:
        """Flip the first hex character of the first line's digest to a different hex character.

        Deterministic: unlike replacing the first literal "0" (a no-op if the digest happens
        to start with a non-zero hex digit), this always changes the digest, regardless of its
        content.
        """
        p = self.root / f"v{version}" / "SHASUMS256.txt"
        text = p.read_text()
        c = text[0]
        flipped = "0" if c != "0" else "1"
        p.write_text(flipped + text[1:])

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.root, ignore_errors=True)
