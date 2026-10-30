"""Plain-English definitions shown as tooltips, "?" buttons and on Help -> Glossary."""

TERMS = {
    "Severity": "Tenable's rating of how bad a vulnerability is if exploited: Critical, High, Medium, Low or Info. "
                "Based mostly on CVSS.",
    "VPR": "Vulnerability Priority Rating (0-10) from Tenable. Unlike CVSS it changes over time with threat "
           "intelligence: a high VPR means attackers are actively using or likely to use this flaw.",
    "CVSS v3": "Common Vulnerability Scoring System base score (0-10): how severe the flaw is in theory, "
               "independent of whether anyone is exploiting it.",
    "CVE": "Common Vulnerabilities and Exposures ID, the public identifier for a specific flaw (e.g. CVE-2023-20198).",
    "Plugin": "A Tenable check. Each plugin tests for one issue; its ID links to Tenable's description and solution.",
    "Exploit available": "Public exploit code or a tool exists for this flaw, so it is much easier to attack.",
    "State": "Open: still present at the last scan. Reopened: was fixed, then found again. Fixed: no longer found.",
    "Risk score": "This app's 0-100 priority score per finding and per device. It combines VPR (or CVSS), whether "
                  "an exploit exists, how long the finding has been open and, for devices, contract / end-of-life / "
                  "software status. Click a device to see exactly how its score was built.",
    "Risk band": "Critical >= 75, High >= 50, Elevated >= 25, otherwise Low.",
    "First / last found": "When Tenable first and most recently saw this finding on the device.",
    "Days open": "Days since Tenable first found the finding.",
    "Contract": "Cisco support contract coverage for the device's serial number, from Cisco's Serial Number to "
                "Information API.",
    "Software status": "How the release the device runs compares with Cisco's suggested release for its model "
                       "(Software Suggestion API).",
    "Cisco suggested": "The release(s) Cisco currently recommends for this model.",
    "Lifecycle": "Cisco end-of-life status from the EoX API: end of sale, last date of support (LDoS) and so on.",
    "LDoS": "Last Date of Support: after this Cisco provides no more fixes or support for the hardware.",
    "End of sale": "The date Cisco stopped selling the product. Support continues until LDoS.",
    "Orderable PID": "The full Cisco product ID as ordered, e.g. C9300-48P-E. The base PID drops the licence "
                     "suffix (C9300-48P).",
    "Model": "Hardware model (Cisco product ID) from AKiPS ENTITY-MIB or Tenable plugin output.",
    "Serial": "Chassis serial number. Each stack member has its own.",
    "Stage": "Enrichment diagnostics: the first step where this device's hardware / Cisco data went missing.",
    "Matched by": "How the AKiPS device was matched to the Tenable device: alias file, IP, sysName or name.",
    "Change": "New: not present at the previous pull. Reopened: was gone at the previous pull but seen earlier.",
    "Fleet risk": "The average risk score of the riskiest quarter of devices, a single number for the network's "
                  "overall exposure.",
    "Time to fix": "Days from when Tenable first found a finding to the first pull where it was gone.",
    "Priority": "Remediation ranking: risk removed divided by the square root of devices touched, so fixes "
                "that close many severe findings on few devices come first.",
    "Confidence": "For OS upgrades: Confirmed (fixed releases are at or below the target), Likely (Cisco "
                  "suggests the target), Check (some fixes need a newer release), Find release (no target known).",
}

# Table column -> glossary term (used for header tooltips).
COLUMNS = {
    "severity": "Severity", "vpr": "VPR", "max_vpr": "VPR", "cvss3": "CVSS v3", "cves": "CVE",
    "plugin_id": "Plugin", "plugin_name": "Plugin", "exploit_available": "Exploit available",
    "exploitable": "Exploit available", "state": "State", "first_found": "First / last found",
    "last_found": "First / last found", "risk": "Risk score", "risk_band": "Risk band", "days_open": "Days open",
    "contract": "Contract", "contract_end": "Contract", "sw_status": "Software status",
    "recommended_sw": "Cisco suggested", "lifecycle": "Lifecycle", "ldos": "LDoS", "end_of_sale": "End of sale",
    "orderable_pid": "Orderable PID", "model": "Model", "serial": "Serial", "serials": "Serial", "stage": "Stage",
    "match_method": "Matched by", "change": "Change", "priority": "Priority", "confidence": "Confidence",
}


def tooltip(column):
    term = COLUMNS.get(column)
    return f"<b>{term}</b><br>{TERMS[term]}" if term else None
