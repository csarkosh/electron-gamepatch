"""Serve a dist/ directory the way a GitHub release does: <base>/v<version>/<asset>."""
from __future__ import annotations

import functools
import http.server
import shutil
import tempfile
import threading
from pathlib import Path


class _Handler(http.server.SimpleHTTPRequestHandler):
    """Answers HTTP/1.1 and keeps quiet.

    Both settings must live on the handler *class*: the server instantiates it per request, so
    attributes set on a functools.partial wrapper are never seen (that is what this file used to
    do, which is why it logged every request and answered HTTP/1.0 regardless).

    HTTP/1.1 is what GitHub's release CDN speaks, and it keeps the socket open after the body
    instead of signalling end-of-response by closing it. Under HTTP/1.0, Node 22.23.1's bundled
    undici intermittently dies on that close with `assert(!this.paused)` in `Parser.finish` when
    the download is paused for backpressure, taking electron's install.js down with it.
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args, **kwargs):
        pass


class Mirror:
    def __init__(self, dist: Path, version: str):
        self.root = Path(tempfile.mkdtemp(prefix="mirror-"))
        rel = self.root / f"v{version}"
        rel.mkdir()
        for p in dist.iterdir():
            if p.suffix == ".zip" or p.name == "SHASUMS256.txt":
                shutil.copy2(p, rel / p.name)
        handler = functools.partial(_Handler, directory=str(self.root))
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
