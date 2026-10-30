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
# Device-level serial numbers some Cisco platforms expose outside ENTITY-MIB. Queried as optional
# extras: used only when a chassis has no entPhysicalSerialNum. Missing attributes are ignored.
DEVICE_SERIAL_ATTRS = [
    "OLD-CISCO-CHASSIS-MIB.chassisId",
    "CISCO-STACK-MIB.chassisSerialNumberString",
]
LINE_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s*=\s?(.*)$")
CHASSIS_RE = re.compile(r"^\s*(chassis|3)\b|\(3\)", re.I)
# Used when a device reports no entPhysicalClass at all: names that denote a chassis / stack member.
CHASSIS_NAME_RE = re.compile(r"^\s*(chassis|switch\s*\d+|stack\s*member\s*\d+|\d+)\s*$", re.I)
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


def _clean_serial(value):
    value = (value or "").strip()
    return "" if value.lower() in PLACEHOLDER_SERIALS else value


def _chassis_entities(entities):
    """Pick the chassis entities of one device: by entPhysicalClass when the device reports it,
    otherwise by name ("Switch 2", "Chassis", "1"), otherwise the lowest-index entity with a model."""
    if any(ent.get("class") for _child, ent in entities):
        return [(c, e) for c, e in entities if CHASSIS_RE.search(e.get("class", ""))]
    named = [(c, e) for c, e in entities if CHASSIS_NAME_RE.match(e.get("name", "")) and (e.get("model") or e.get("serial"))]
    if named:
        return named
    with_model = sorted(((c, e) for c, e in entities if e.get("model")), key=lambda ce: _child_sort_key(ce[0]))
    return with_model[:1]


def chassis_rows(sys_lines, entity_lines):
    """Combine sys + ENTITY-MIB values into one row per chassis (standalone box or stack member)."""
    sys_info = defaultdict(dict)
    for device, _child, attr, value in sys_lines:
        if attr.endswith("ip4addr"):
            sys_info[device]["ip"] = value
        elif attr.endswith("sysDescr"):
            sys_info[device]["sys_descr"] = value
        elif any(attr.endswith(a.split(".")[-1]) for a in DEVICE_SERIAL_ATTRS) and _clean_serial(value):
            sys_info[device].setdefault("serial", _clean_serial(value))

    attr_key = {v: k for k, v in ENTITY_ATTRS.items()}
    per_device = defaultdict(dict)
    for device, child, attr, value in entity_lines:
        key = attr_key.get(attr) or next((k for a, k in attr_key.items() if attr.endswith(a.split(".")[-1])), None)
        if key:
            per_device[device].setdefault(child, {})[key] = value

    rows = []
    for device, children in per_device.items():
        entries = []
        for child, ent in _chassis_entities(list(children.items())):
            serial = _clean_serial(ent.get("serial"))
            if serial or ent.get("model"):
                entries.append((child, ent, serial))
        entries.sort(key=lambda e: _child_sort_key(e[0]))
        # Device-level serial (chassisId etc.) fills a single chassis that has none.
        device_serial = sys_info[device].get("serial")
        if device_serial and len(entries) == 1 and not entries[0][2]:
            entries[0] = (entries[0][0], entries[0][1], device_serial)
        for ordinal, (child, ent, serial) in enumerate(entries, start=1):
            m = MEMBER_RE.search(ent.get("name", "") or ent.get("descr", ""))
            rows.append({
                "akips_device": device,
                "ip": sys_info[device].get("ip"),
                "sys_descr": sys_info[device].get("sys_descr"),
                "descr": (ent.get("descr") or "").strip(),
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
        (entity_lines if "entPhysical" in cmd else sys_lines).extend(parse_mget(text))
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

    def raw_responses(self, log=None):
        """Run every inventory query and return {command: raw text} (used for --dump-samples)."""
        log = log or (lambda msg: None)
        cmds = list(SYS_COMMANDS.values()) + [f"mget text * * {attr}" for attr in ENTITY_ATTRS.values()]
        raw = {cmd: self.query(cmd) for cmd in cmds}
        serial_cmd = f"mget text * * {ENTITY_ATTRS['serial']}"
        if not parse_mget(raw[serial_cmd]):
            log("  AKiPS returned no ENTITY-MIB serial numbers; trying a pattern match on the attribute name.")
            raw[serial_cmd + " (pattern)"] = self._optional("mget text * * /entPhysicalSerialNum/")
        for attr in DEVICE_SERIAL_ATTRS:  # optional extras; absent on most AKiPS installs
            raw[f"mget text * sys {attr}"] = self._optional(f"mget text * sys {attr}")
        return raw

    def _optional(self, cmd):
        try:
            return self.query(cmd)
        except Exception:  # noqa: BLE001 - an unsupported optional query must not fail the pull
            return ""

    def device_dump(self, device):
        """Every attribute AKiPS holds for one device (for finding where model/serial live)."""
        return self.query(f"mget text {device} * *")

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
