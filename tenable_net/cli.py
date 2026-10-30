"""Command-line entrypoint: python -m tenable_net <command> ..."""

import argparse
import logging
import sys

from tenable_net import akips, cisco, export, inventory, normalize, reports, summaries

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
    if getattr(args, "with_inventory", False):
        _refresh_inventory(args, tio=tio, strict=False)


def _refresh_inventory(args, tio=None, strict=True):
    """AKiPS + Tenable inventory, then Cisco lookups, for whichever sources are configured."""
    from tenable_net.client import get_client

    log = summaries.console.print
    use_akips = not getattr(args, "skip_akips", False)
    use_tenable = not getattr(args, "skip_tenable", False)
    use_cisco = not getattr(args, "skip_cisco", False)
    if use_akips and not akips.configured():
        log("[yellow]AKiPS not configured (AKIPS_URL in .env); using Tenable plugin output only.[/yellow]")
        use_akips = False
    if use_cisco and not cisco.configured():
        log("[yellow]Cisco API not configured (CISCO_CLIENT_ID/SECRET in .env); skipping lifecycle/contract.[/yellow]")
        use_cisco = False
    inventory.refresh_all(
        args.cache_dir,
        tio=(tio or get_client()) if use_tenable else None,
        akips_client=akips.get_client() if use_akips else None,
        cisco_client=cisco.get_client() if use_cisco else None,
        force_cisco=getattr(args, "force", False),
        strict=strict, log=log, samples=getattr(args, "dump_samples", 0),
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
    inv = inventory.load_inventory(args.cache_dir)
    for path in reports.write_reports(findings, assets, out_dir=args.out, xlsx=not args.no_xlsx, inventory=inv):
        summaries.console.print(f"[green]wrote[/green] {path}")


def cmd_inventory(args):
    _refresh_inventory(args)
    summaries.hardware(inventory.load_inventory(args.cache_dir), top=args.top)


def cmd_hardware(args):
    summaries.hardware(inventory.load_inventory(args.cache_dir), top=args.top)


def cmd_cisco_test(args):
    """Check the token and each Cisco API separately, using a real serial/model when cached."""
    serial, pid = inventory.sample_cisco_keys(args.cache_dir)
    enabled = cisco.enabled_apis()
    failed = False
    for key, name, ok, detail in cisco.diagnose(cisco.get_client(), serial=args.serial or serial, pid=args.pid or pid):
        mark = {True: "[green]OK[/green]  ", False: "[red]FAIL[/red]", None: "[dim]skip[/dim]"}[ok]
        note = "" if key == "token" or key in enabled else "  [dim](not enabled in CISCO_APIS)[/dim]"
        summaries.console.print(f"{mark} {name}: {detail}{note}")
        if ok is False and (key == "token" or key in enabled):
            failed = True
    summaries.console.print(f"\nEnabled APIs (CISCO_APIS): {', '.join(sorted(enabled)) or 'none'}")
    if failed:
        raise RuntimeError("An enabled Cisco API check failed (see above). Disable APIs your app "
                           "doesn't have via CISCO_APIS or Settings -> Cisco.")


def cmd_cisco_refresh(args):
    inventory.refresh_cisco(args.cache_dir, cisco.get_client(), force=args.force, log=summaries.console.print)
    summaries.hardware(inventory.load_inventory(args.cache_dir), top=args.top)


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
    p.add_argument("--with-inventory", action="store_true",
                   help="also refresh hardware inventory (AKiPS + Tenable) and Cisco lifecycle/contract")
    p.set_defaults(func=cmd_pull)

    p = sub.add_parser("inventory", help="pull hardware inventory (AKiPS + Tenable) and Cisco lifecycle/contract")
    p.add_argument("--skip-akips", action="store_true", help="don't query AKiPS")
    p.add_argument("--skip-tenable", action="store_true", help="don't export Tenable inventory plugins")
    p.add_argument("--skip-cisco", action="store_true", help="don't query the Cisco Support APIs")
    p.add_argument("--force", action="store_true", help="re-query Cisco even if cached results are fresh")
    p.add_argument("--dump-samples", type=int, nargs="?", const=3, default=0, metavar="N",
                   help="write N raw records per source to cache/samples/ for checking (scrub before sharing)")
    p.add_argument("--top", type=int, default=20, help="rows per table")
    p.set_defaults(func=cmd_inventory)

    p = sub.add_parser("hardware", help="show cached hardware lifecycle/contract summary")
    p.add_argument("--top", type=int, default=20, help="rows per table")
    p.set_defaults(func=cmd_hardware)

    p = sub.add_parser("cisco-test", help="check the Cisco token and each Support API (contract, software, EoX)")
    p.add_argument("--serial", help="serial number to test contract lookup with (default: one from inventory)")
    p.add_argument("--pid", help="product ID to test software suggestions with (default: one from inventory)")
    p.set_defaults(func=cmd_cisco_test)

    p = sub.add_parser("cisco-refresh", help="re-query Cisco EoX + contract coverage for cached inventory")
    p.add_argument("--force", action="store_true", help="ignore the 7-day cache")
    p.add_argument("--top", type=int, default=20, help="rows per table")
    p.set_defaults(func=cmd_cisco_refresh)

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
