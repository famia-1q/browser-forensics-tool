from __future__ import annotations

import os
import sys
from pathlib import Path

import PyInstaller.__main__

ROOT = Path(__file__).resolve().parent.parent
SEP = os.pathsep


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist"
    work = out.parent / "build"
    PyInstaller.__main__.run([
        str(ROOT / "packaging" / "bft_app.py"),
        "--name", "BrowserForensics",
        "--onefile" if sys.platform.startswith("win") else "--onedir",
        "--windowed",
        "--noconfirm",
        "--clean",
        "--paths", str(ROOT),
        "--collect-submodules", "bft",
        "--add-data", "%s%sbft/web" % (ROOT / "bft" / "web" / "index.html", SEP),
        "--add-data", "%s%stools" % (ROOT / "tools" / "make_demo_evidence.py", SEP),
        "--distpath", str(out),
        "--workpath", str(work),
        "--specpath", str(work),
    ])


if __name__ == "__main__":
    main()
