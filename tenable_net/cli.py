"""Command-line entrypoint: python -m tenable_net <command> ..."""

import argparse
import logging
import sys

from tenable_net import export, normalize, reports, summaries

SEVERITIES = ["critical", "high", "medium", "low", "info"]
STATES = ["open", "reopened", "fixed"]


def _pull(args):
    from tenable_net.client import get_client

    tio = get_client()
    severity = args.severity or (SEVERITIES if args.include_info else SEVERITIES[:-1])
    meta = export.pull(
        tio, severity, args.state, since_days=args.since, include_output=args.plugin_output,
        skip_assets=args.skip_assets, cache_dir=args.cache_dir, log=summaries.console.print,
    )
    summaries.console.print(
        f"[green]Cached {meta['vuln_count']} findings and {meta['asset_count']} assets in {args.cache_dir}/[/green]"
    )


def _load(args):
    if getattr(args, "refresh", False):
        _pull(args)
    vulns, assets, meta = export.load_cache(args.cache_dir)
    findings = normalize.findings_frame(vulns, include_info=args.include_info)
    return findings, normalize.assets_frame(assets), meta


def cmd_pull(args):
    _pull(args)


def cmd_summary(args):
    findings, _, meta = _load(args)
    summaries.summary(findings, meta, top=args.top)


def cmd_report(args):
    findings, assets, _ = _load(args)
    for path in reports.write_reports(findings, assets, out_dir=args.out, xlsx=not args.no_xlsx):
        summaries.console.print(f"[green]wrote[/green] {path}")


def cmd_device(args):
    findings, _, _ = _load(args)
    summaries.device(findings, args.query)


def cmd_gui(args):
    try:
        from tenable_net.gui.app import main as gui_main
    except ImportError as exc:
        raise RuntimeError(f"The GUI needs PySide6: pip install PySide6 ({exc})") from exc
    gui_main(cache_dir=args.cache_dir)


def cmd_search(args):
    findings, _, _ = _load(args)
    summaries.search(findings, args.query)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="tenable_net",
        description="Query Tenable Vulnerability Management via bulk exports and report on the results.",
    )
    parser.add_argument("--cache-dir", default=str(export.DEFAULT_CACHE_DIR), help="where pulled data is cached")
    parser.add_argument("-v", "--verbose", action="store_true", help="show pyTenable/HTTP debug logging")

    pull_opts = argparse.ArgumentParser(add_help=False)
    pull_opts.add_argument("--severity", nargs="+", choices=SEVERITIES, help="default: low and above")
    pull_opts.add_argument("--state", nargs="+", choices=STATES, default=["open", "reopened"])
    pull_opts.add_argument("--since", type=int, metavar="DAYS", help="only findings seen in the last N days")
    pull_opts.add_argument("--plugin-output", action="store_true", help="include raw plugin output (larger)")
    pull_opts.add_argument("--skip-assets", action="store_true", help="skip the asset inventory export")

    read_opts = argparse.ArgumentParser(add_help=False)
    read_opts.add_argument("--refresh", action="store_true", help="pull fresh data before running")
    read_opts.add_argument("--include-info", action="store_true", help="include informational findings")

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("pull", parents=[pull_opts], help="export data from Tenable into the local cache")
    p.add_argument("--include-info", action="store_true", help="also export informational findings")
    p.set_defaults(func=cmd_pull)

    p = sub.add_parser("summary", parents=[pull_opts, read_opts], help="terminal overview")
    p.add_argument("--top", type=int, default=15, help="rows per table")
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("report", parents=[pull_opts, read_opts], help="write CSV + Excel reports")
    p.add_argument("--out", help="output directory (default output/<timestamp>)")
    p.add_argument("--no-xlsx", action="store_true", help="CSV only")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("device", parents=[pull_opts, read_opts], help="all findings for one device")
    p.add_argument("query", help="hostname (substring) or exact IP")
    p.set_defaults(func=cmd_device)

    p = sub.add_parser("search", parents=[pull_opts, read_opts], help="devices affected by a CVE / plugin")
    p.add_argument("query", help="CVE ID, plugin ID, or text in the plugin name")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("gui", help="open the desktop app")
    p.set_defaults(func=cmd_gui)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)
    try:
        args.func(args)
    except FileNotFoundError as exc:
        summaries.console.print(f"[red]{exc}[/red]")
        return 1
    except RuntimeError as exc:
        summaries.console.print(f"[red]{exc}[/red]")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
