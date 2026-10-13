#!/usr/bin/env python3
"""
DastDay — a clean-room, open-source web security proxy and testing toolkit.

Entry point. Starts the intercepting proxy and the web UI.

Usage:
    python main.py                       # proxy on :8080, UI on :8000
    python main.py --proxy-port 8081 --ui-port 8001
"""

import argparse
import asyncio
import sys

# Make the package importable whether run from repo root or elsewhere.
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))

from dastday.app import run


def main() -> None:
    p = argparse.ArgumentParser(description="DastDay web security proxy")
    p.add_argument("--proxy-host", default="127.0.0.1")
    p.add_argument("--proxy-port", type=int, default=8080)
    p.add_argument("--ui-host", default="127.0.0.1")
    p.add_argument("--ui-port", type=int, default=8000)
    p.add_argument("--db", default="dastday.db")
    args = p.parse_args()

    try:
        asyncio.run(run(
            proxy_host=args.proxy_host, proxy_port=args.proxy_port,
            ui_host=args.ui_host, ui_port=args.ui_port, db_path=args.db,
        ))
    except KeyboardInterrupt:
        print("\n[dastday] shutting down")


if __name__ == "__main__":
    main()
