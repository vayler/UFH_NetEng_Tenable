"""Read-only AKiPS client: chassis / stack-member model and serial numbers from ENTITY-MIB.

AKiPS answers `mget` queries on its `api-db` endpoint with one line per value:

    <device> <child> <attribute> = <value>

e.g. `core-sw-01 sys SNMPv2-MIB.sysDescr = Cisco IOS Software ...` or
`core-sw-01 1000 ENTITY-MIB.entPhysicalSerialNum = FOC1234X0YZ`. The exact child naming for
ENTITY-MIB rows varies, so rows are grouped by (device, child) without assuming a format.
Run `python -m tenable_net inventory --dump-samples` to capture real responses for checking.
"""

import os
import re
from collections import defaultdict

from dotenv import load_dotenv

from tenable_net.client import MissingCredentials, env_path

# One query per attribute keeps the command syntax as plain as possible.
SYS_COMMANDS = {
    "ip": "mget text * sys ip4addr",
    "sys_descr": "mget text * sys SNMPv2-MIB.sysDescr",
}
ENTITY_ATTRS = {
    "class": "ENTITY-MIB.entPhysicalClass",
    "name": "ENTITY-MIB.entPhysicalName",
    "descr": "ENTITY-MIB.entPhysicalDescr",
    "model": "ENTITY-MIB.entPhysicalModelName",
    "serial": "ENTITY-MIB.entPhysicalSerialNum",
    "sw_version": "ENTITY-MIB.entPhysicalSoftwareRev",
}
LINE_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s*=\s?(.*)$")
CHASSIS_RE = re.compile(r"^\s*(chassis|3)\b|\(3\)", re.I)
PLACEHOLDER_SERIALS = {"", "n/a", "na", "none", "unknown", "0", "-"}
MEMBER_RE = re.compile(r"(?:switch|member|chassis|slot)\s*(\d+)", re.I)


def parse_mget(text):
    """Parse mget text output into a list of (device, child, attribute, value)."""
    out = []
    for line in text.splitlines():
        m = LINE_RE.match(line.strip())
        if m:
            out.append((m.group(1), m.group(2), m.group(3), m.group(4).strip().strip('"')))
    return out


def chassis_rows(sys_lines, entity_lines):
    """Combine sys + ENTITY-MIB values into one row per chassis (standalone box or stack member)."""
    sys_info = defaultdict(dict)
    for device, _child, attr, value in sys_lines:
        if attr.endswith("ip4addr"):
            sys_info[device]["ip"] = value
        elif attr.endswith("sysDescr"):
            sys_info[device]["sys_descr"] = value

    attr_key = {v: k for k, v in ENTITY_ATTRS.items()}
    entities = defaultdict(dict)
    for device, child, attr, value in entity_lines:
        key = attr_key.get(attr) or next((k for a, k in attr_key.items() if attr.endswith(a.split(".")[-1])), None)
        if key:
            entities[(device, child)][key] = value

    rows = []
    by_device = defaultdict(list)
    for (device, child), ent in entities.items():
        if not CHASSIS_RE.search(ent.get("class", "")):
            continue
        serial = (ent.get("serial") or "").strip()
        if serial.lower() in PLACEHOLDER_SERIALS:
            serial = ""
        if not serial and not ent.get("model"):
            continue
        by_device[device].append((child, ent, serial))

    for device, entries in by_device.items():
        entries.sort(key=lambda e: _child_sort_key(e[0]))
        for ordinal, (child, ent, serial) in enumerate(entries, start=1):
            m = MEMBER_RE.search(ent.get("name", "") or ent.get("descr", ""))
            rows.append({
                "akips_device": device,
                "ip": sys_info[device].get("ip"),
                "sys_descr": sys_info[device].get("sys_descr"),
                "entity_index": child,
                "member": int(m.group(1)) if m else ordinal,
                "member_name": ent.get("name") or "",
                "model": (ent.get("model") or "").strip(),
                "serial": serial,
                "sw_version": (ent.get("sw_version") or "").strip(),
            })
    return rows


def rows_from_raw(raw):
    """Chassis rows from {command: raw mget text}, as returned by AkipsClient.raw_responses()."""
    sys_lines, entity_lines = [], []
    for cmd, text in raw.items():
        (entity_lines if "ENTITY-MIB" in cmd else sys_lines).extend(parse_mget(text))
    return chassis_rows(sys_lines, entity_lines)


def _child_sort_key(child):
    digits = re.findall(r"\d+", child)
    return (int(digits[-1]) if digits else 0, child)


class AkipsClient:
    def __init__(self, url, username, password, verify=True, timeout=120):
        import requests

        self.url = url.rstrip("/") + "/api-db"
        self.auth = {"username": username, "password": password}
        self.session = requests.Session()
        self.session.verify = verify
        self.timeout = timeout

    def query(self, cmd):
        resp = self.session.get(self.url, params={**self.auth, "cmds": cmd}, timeout=self.timeout)
        resp.raise_for_status()
        text = resp.text
        if text.lstrip().upper().startswith("ERROR"):
            raise RuntimeError(f"AKiPS error for `{cmd}`: {text.strip()[:300]}")
        return text

    def raw_responses(self):
        """Run every inventory query and return {command: raw text} (used for --dump-samples)."""
        cmds = list(SYS_COMMANDS.values()) + [f"mget text * * {attr}" for attr in ENTITY_ATTRS.values()]
        return {cmd: self.query(cmd) for cmd in cmds}

    def test(self):
        """Cheap connectivity/credentials check. Returns the number of devices with sysDescr."""
        return len(parse_mget(self.query(SYS_COMMANDS["sys_descr"])))


def configured():
    load_dotenv(env_path())
    return bool(os.getenv("AKIPS_URL"))


def get_client(url=None, username=None, password=None):
    load_dotenv(env_path())
    url = url or os.getenv("AKIPS_URL")
    username = username or os.getenv("AKIPS_USER", "api-ro")
    password = password or os.getenv("AKIPS_PASSWORD")
    if not url or not password:
        raise MissingCredentials("AKIPS_URL and AKIPS_PASSWORD must be set (in .env or Settings).")
    verify = os.getenv("AKIPS_CA_BUNDLE") or True
    return AkipsClient(url, username, password, verify=verify)
