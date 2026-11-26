"""CLI entrypoint for `python3 -m scripts.bisect_agent`."""

from .controller import main

if __name__ == "__main__":
    raise SystemExit(main())
