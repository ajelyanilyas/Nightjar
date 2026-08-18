"""Nightjar command-line interface.

    python -m nightjar.cli replay --out data
    python -m nightjar.cli detect --logs data --rules rules
    python -m nightjar.cli serve --logs data --rules rules
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pipeline import run_detection
from .replay import SCENARIOS, generate_scenario

_SEV_COLOR = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[96m",
    "info": "\033[90m",
}
_RESET = "\033[0m"


def _color(text: str, sev: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_SEV_COLOR.get(sev, '')}{text}{_RESET}"


def cmd_replay(args: argparse.Namespace) -> int:
    counts = generate_scenario(args.out, args.scenario, seed=args.seed)
    print(f"Wrote scenario '{args.scenario}' to {Path(args.out).resolve()}")
    for name, n in counts.items():
        print(f"  {name:<18} {n:>4} lines")
    print("\nNext:  python -m nightjar.cli detect "
          f"--logs {args.out} --rules rules")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    result = run_detection(args.logs, args.rules)

    if args.json:
        payload = {
            "summary": result.summary(),
            "alerts": [a.to_dict() for a in result.alerts],
        }
        print(json.dumps(payload, indent=2))
        return 0

    use_color = sys.stdout.isatty() and not args.no_color
    print(f"Loaded {len(result.rules)} rules, parsed {len(result.events)} events.")
    print(f"\n{'='*70}\n {len(result.alerts)} ALERT(S)\n{'='*70}")

    for a in result.alerts:
        tag = _color(f"[{a.severity.upper()}]", a.severity, use_color)
        mitre = f" {','.join(a.mitre)}" if a.mitre else ""
        when = a.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        ip = a.src_ip or "-"
        print(f"\n{tag} {a.title}{mitre}")
        print(f"    when : {when}   src_ip: {ip}   events: {a.count}")
        if a.events:
            print(f"    evid : {a.events[0].raw[:100]}")

    sev = result.by_severity()
    if sev:
        print(f"\n{'-'*70}")
        print("  by severity: " + "  ".join(f"{k}={v}" for k, v in sev.items()))
        offenders = result.top_offenders(5)
        if offenders:
            print("  top offenders: "
                  + "  ".join(f"{o['ip']}({o['alerts']})" for o in offenders))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        print("The 'serve' command needs FastAPI + uvicorn:\n"
              "  pip install -r requirements.txt", file=sys.stderr)
        return 1

    from .api.app import create_app

    app = create_app(logs_dir=args.logs, rules_dir=args.rules)
    print(f"Nightjar dashboard -> http://{args.host}:{args.port}")
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nightjar", description="Detection-as-Code mini-SIEM.")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("replay", help="generate a realistic attack scenario")
    r.add_argument("--out", default="data", help="output directory (default: data)")
    r.add_argument("--scenario", choices=SCENARIOS, default="full")
    r.add_argument("--seed", type=int, default=None, help="seed for reproducible output")
    r.set_defaults(func=cmd_replay)

    d = sub.add_parser("detect", help="run detections over a log directory")
    d.add_argument("--logs", default="data", help="directory of log files")
    d.add_argument("--rules", default="rules", help="directory of YAML rules")
    d.add_argument("--json", action="store_true", help="emit JSON instead of text")
    d.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    d.set_defaults(func=cmd_detect)

    s = sub.add_parser("serve", help="launch the live dashboard")
    s.add_argument("--logs", default="data")
    s.add_argument("--rules", default="rules")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to a legacy codepage (cp1252) that can't encode
    # arrows or arbitrary bytes from log lines; force UTF-8 where supported.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
