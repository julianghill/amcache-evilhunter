#!/usr/bin/env python3

"""
AmCache-EvilHunter: parse and analyze a Windows Amcache.hve registry hive.
by Cristian Souza (cristianmsbr@gmail.com)
"""

import argparse
import json
import sys
import csv
import re
import os
import html
from pathlib import Path
from functools import lru_cache
from datetime import datetime, timedelta

import requests
from requests.exceptions import HTTPError

from Registry.Registry import Registry as RegistryHive
from Registry.RegistryParse import ParseException as RegistryParseException

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn

VERSION = "0.0.4"
VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"
OPENTIP_API_URL = "https://opentip.kaspersky.com/api/v1/search/hash?request={hash}"
VT_TEST_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Core fields to persist for SHA-1–bearing records
KEEP_FIELDS = {
    # Common uninstall/AppV entries
    "ProgramId", "ProgramInstanceId", "Name", "Version", "Publisher",
    "Language", "InstallDate", "Source", "RootDirPath", "HiddenArp",
    "UninstallString", "RegistryKeyPath", "MsiPackageCode",
    "MsiProductCode", "MsiInstallDate", "(default)", "FilePath",
    # Amcache-specific entries
    "SHA-1", "LowerCaseLongPath", "OriginalFileName", "BinFileVersion",
    "BinaryType", "ProductName", "ProductVersion", "LinkDate",
    "BinProductVersion", "Size", "Usn",
    "IsOsComponent",
    # Computed date
    "RecordDate",
}

PREFERRED_FIELD_ORDER = [
    "Category",
    "RecordName",
    "SHA-1",
    "Name",
    "OriginalFileName",
    "FilePath",
    "LowerCaseLongPath",
    "ProductName",
    "Publisher",
    "ProductVersion",
    "BinFileVersion",
    "BinProductVersion",
    "BinaryType",
    "Size",
    "Language",
    "IsOsComponent",
    "RecordDate",
    "LinkDate",
    "InstallDate",
    "MsiInstallDate",
    "MsiPackageCode",
    "MsiProductCode",
    "ProgramId",
    "ProgramInstanceId",
    "RootDirPath",
    "Source",
    "UninstallString",
    "RegistryKeyPath",
    "(default)",
    "Version",
    "Usn",
]

console = Console()


def prompt_overwrite(path):
    if path.exists():
        ans = input(f"File {path} exists. Overwrite? [y/N]: ")
        if ans.lower() != 'y':
            print("Aborted: file not overwritten.", file=sys.stderr)
            sys.exit(0)


def find_suspicious(data):
    """
    Keep only records whose FilePath basename exactly matches one of our
    known suspicious executables (case‐insensitive), ends with .exe,
    OR is a one‐letter/one‐digit name, OR looks like a random hex string.
    """
    suspicious_patterns = {
        "lb3", "lockbit", "ryuk", "darkside", "conti",
        "maze", "emotet", "trickbot", "qbot", "cerber",
        "svchost", "scvhost", "svch0st", "svhost",
        "rundll32", "rundll", "explorer", "expl0rer", "expiorer",
        "csrss", "csrs", "winlogon", "winlog0n", "winlogin",
        "lsass", "lsas", "isass", "services", "service", "svces",
        "dllhost", "dihost", "dllhst", "conhost", "conhost1",
        "conhost64", "spoolsv", "splsv", "spools", "taskhostw",
        "taskhost", "taskhost64", "taskhostw1", "wmiprvse",
        "mshta", "mshta32", "wscript", "wscript1", "cscript",
        "cscript5", "regsvr32", "regsvr321",
    }
    hex_re = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)

    filtered = {}
    for cat, recs in data.items():
        keep = {}
        for rec, vals in recs.items():
            fp = vals.get("Name", "")
            name = Path(fp).name.lower()
            if not name.endswith(".exe"):
                continue
            stem = name[:-4]
            if (
                stem in suspicious_patterns
                or len(stem) == 1
                or stem.isdigit()
                or hex_re.match(stem)
            ):
                keep[rec] = vals
        if keep:
            filtered[cat] = keep
    return filtered


def missing_publisher(data):
    """
    Keep only records where the Publisher field is missing or empty.
    """
    filtered = {}
    for cat, recs in data.items():
        keep = {}
        for rec, vals in recs.items():
            if not vals.get("Publisher"):
                keep[rec] = vals
        if keep:
            filtered[cat] = keep
    return filtered


class AmcacheParser:
    """Parser for offline Amcache.hve registry hive."""
    def __init__(self, hive_path, start=None, end=None):
        if not hive_path.exists():
            raise FileNotFoundError(f"Hive file not found: {hive_path}")
        try:
            self.registry = RegistryHive(str(hive_path))
        except RegistryParseException:
            console.print(
                f"[bold red]Error:[/] '{hive_path}' is not a valid registry hive.",
                style="red"
            )
            sys.exit(1)

        self.start = start
        self.end = end

    def compute_record_date(self, vals, rec_key):
        """Convert Windows FILETIME values to datetime, fallback to key timestamp."""
        def filetime_to_dt(ft_raw):
            try:
                if isinstance(ft_raw, bytes):
                    ft_int = int.from_bytes(ft_raw, "little", signed=False)
                elif isinstance(ft_raw, int):
                    ft_int = ft_raw
                else:
                    return None
                return datetime(1601, 1, 1) + timedelta(microseconds=ft_int // 10)
            except (TypeError, ValueError):
                return None

        for fname in ("LastModifiedTime", "LastWriteTime", "ModifiedTime", "CreationTime"):
            dt = filetime_to_dt(vals.get(fname))
            if dt:
                return dt
        return rec_key.timestamp()

    def parse(self):
        """Walk the Amcache hive and collect record values."""
        root = self.registry.open("Root")
        subs = {k.name(): k for k in root.subkeys()}
        parent = subs.get("InventoryApplicationFile") or subs.get("File") or root

        data = {"Amcache": {}}
        for rec in parent.subkeys():
            vals = {v.name(): v.value() for v in rec.values()}
            vals["FilePath"] = vals.get("LowerCaseLongPath", rec.name())

            record_dt = self.compute_record_date(vals, rec)
            vals["RecordDate"] = record_dt.isoformat()

            if "FileId" in vals:
                vals["SHA-1"] = vals.pop("FileId")

            rd = record_dt.date()
            if self.start and rd < self.start.date():
                continue
            if self.end and rd > self.end.date():
                continue

            data["Amcache"][rec.name()] = vals

        return data


def normalize_data(data, trim_sha1=False):
    """Trim whitespace on all strings; optionally strip leading zeros on SHA-1."""
    for recs in data.values():
        for vals in recs.values():
            for k, v in list(vals.items()):
                if isinstance(v, str):
                    nv = v.strip()
                    if trim_sha1 and k in ("SHA-1", "SHA1") and nv.startswith("0000"):
                        nv = nv[4:]
                    vals[k] = nv


def normalize_hash_for_lookup(hash_value):
    """Normalize padded SHA-1 values before external lookups."""
    if not hash_value or not isinstance(hash_value, str):
        return hash_value
    hv = hash_value.strip()
    if len(hv) == 44 and hv.startswith("0000") and re.fullmatch(r"[0-9a-fA-F]{44}", hv):
        return hv[4:]
    return hv


@lru_cache(maxsize=1024)
def lookup_vt(hash_value, api_key):
    """Fetch VT stats for a hash; return (detections, total, ratio)."""
    hash_value = normalize_hash_for_lookup(hash_value)
    if not hash_value:
        return None, None, ""
    try:
        resp = requests.get(
            VT_API_URL.format(hash=hash_value),
            headers={"x-apikey": api_key},
            timeout=15
        )
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        det = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.get(k, 0) for k in stats)
        return det, total, f"{det}/{total}"
    except HTTPError as e:
        if e.response and e.response.status_code == 404:
            return None, None, "N/A"
        return None, None, ""
    except (ValueError, KeyError):
        return None, None, ""


@lru_cache(maxsize=1024)
def lookup_opentip(hash_value, api_key):
    """Fetch OpenTIP FileStatus for a hash; return status or 'N/A'."""
    hash_value = normalize_hash_for_lookup(hash_value)
    if not hash_value:
        return ""
    try:
        resp = requests.get(
            OPENTIP_API_URL.format(hash=hash_value),
            headers={"x-api-key": api_key},
            timeout=15
        )
        resp.raise_for_status()
        data = resp.json()
        status = data.get("FileGeneralInfo", {}).get("FileStatus")
        return status or "N/A"
    except HTTPError as e:
        if e.response and e.response.status_code == 404:
            return "N/A"
        return ""
    except (ValueError, KeyError):
        return ""


def check_vt_connection(api_key):
    """Validate VT API key with a lightweight test request."""
    try:
        resp = requests.get(
            VT_API_URL.format(hash=VT_TEST_HASH),
            headers={"x-apikey": api_key},
            timeout=15
        )
        if resp.status_code in (401, 403):
            console.print(
                "[bold red]Error:[/] VT_API_KEY rejected (unauthorized).",
                style="red"
            )
            return False
        if resp.status_code == 429:
            console.print(
                "[bold red]Error:[/] VT rate limit exceeded during key check.",
                style="red"
            )
            return False
        if resp.status_code not in (200, 404):
            console.print(
                f"[bold red]Error:[/] VT API returned {resp.status_code} during key check.",
                style="red"
            )
            return False
    except requests.RequestException as e:
        console.print(f"[bold red]Error:[/] VT connection failed: {e}", style="red")
        return False

    msg = "VT API key check: OK"
    if resp.status_code == 404:
        msg += " (test hash not found)"
    console.print(f"[bold green]{msg}[/]")
    return True


def prune_record(vals, vt_enabled=False, opentip_enabled=False):
    """Select only the KEEP_FIELDS (plus VT/OpenTIP fields) from vals."""
    if not vals.get("SHA-1"):
        return {}
    out = {}
    fields = set(KEEP_FIELDS)
    if vt_enabled:
        fields.update({"VT_Detections", "VT_TotalEngines", "VT_Ratio"})
    if opentip_enabled:
        fields.add("OpenTIP_FileStatus")
    for field in fields:
        if field == "IsOsComponent":
            continue
        if field in vals:
            out[field] = vals[field]
    out["IsOsComponent"] = bool(vals.get("IsOsComponent"))
    return out


def build_output_headers(vt_enabled, opentip_enabled):
    headers = []
    seen = set()
    for field in PREFERRED_FIELD_ORDER:
        headers.append(field)
        seen.add(field)
    extra = sorted(f for f in KEEP_FIELDS if f not in seen)
    headers.extend(extra)
    if vt_enabled:
        headers += ["VT_Detections", "VT_TotalEngines", "VT_Ratio"]
    if opentip_enabled:
        headers += ["OpenTIP_FileStatus"]
    return headers


def is_detection_hit(vt_enabled, opentip_enabled, vt_detections, ot_status):
    if vt_enabled:
        return vt_detections is not None and vt_detections > 0
    if opentip_enabled:
        return (ot_status or "").lower() == "malware"
    return False


def count_records(data):
    total = 0
    for recs in data.values():
        for vals in recs.values():
            if vals.get("SHA-1"):
                total += 1
    return total


def write_json(path, data, vt_enabled, opentip_enabled, vt_api_key, ot_api_key, only_detections):
    """Write filtered records to JSON file."""
    prompt_overwrite(path)

    total = count_records(data)
    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    )

    with path.open("w", encoding="utf-8") as f:
        with progress:
            task = progress.add_task("Writing JSON", total=total)
            for cat, recs in data.items():
                for rec_name, vals in recs.items():
                    kept = prune_record(vals, vt_enabled, opentip_enabled)
                    if not kept:
                        continue

                    ot_status = ""
                    det = None
                    if vt_enabled:
                        det, tot, ratio = lookup_vt(kept["SHA-1"], vt_api_key)
                        kept["VT_Detections"] = det
                        kept["VT_TotalEngines"] = tot
                        kept["VT_Ratio"] = ratio

                    if opentip_enabled:
                        ot_status = lookup_opentip(kept["SHA-1"], ot_api_key)
                        kept["OpenTIP_FileStatus"] = ot_status

                    if only_detections and (vt_enabled or opentip_enabled):
                        if not is_detection_hit(vt_enabled, opentip_enabled, det, ot_status):
                            progress.advance(task)
                            continue

                    kept["Category"] = cat
                    kept["RecordName"] = rec_name
                    f.write(json.dumps(kept, ensure_ascii=False) + "\n")
                    progress.advance(task)


def write_csv(path, data, vt_enabled, opentip_enabled, vt_api_key, ot_api_key, only_detections):
    """Write filtered records to CSV file."""
    prompt_overwrite(path)

    headers = build_output_headers(vt_enabled, opentip_enabled)

    total = count_records(data)
    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    )

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()

        with progress:
            task = progress.add_task("Writing CSV", total=total)
            for cat, recs in data.items():
                for rec_name, vals in recs.items():
                    kept = prune_record(vals, vt_enabled, opentip_enabled)
                    if not kept:
                        continue

                    row = {"Category": cat, "RecordName": rec_name, **kept}

                    ot_status = ""
                    det = None
                    if vt_enabled:
                        det, tot, ratio = lookup_vt(kept["SHA-1"], vt_api_key)
                        row["VT_Detections"] = det
                        row["VT_TotalEngines"] = tot
                        row["VT_Ratio"] = ratio

                    if opentip_enabled:
                        ot_status = lookup_opentip(kept["SHA-1"], ot_api_key)
                        row["OpenTIP_FileStatus"] = ot_status

                    if only_detections and (vt_enabled or opentip_enabled):
                        if not is_detection_hit(vt_enabled, opentip_enabled, det, ot_status):
                            progress.advance(task)
                            continue

                    writer.writerow(row)
                    progress.advance(task)


def write_html(path, data, vt_enabled, opentip_enabled, vt_api_key, ot_api_key, only_detections):
    """Write filtered records to HTML file."""
    prompt_overwrite(path)

    headers = [h for h in build_output_headers(vt_enabled, opentip_enabled) if h != "Category"]
    rows = []

    total = count_records(data)
    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    )

    with progress:
        task = progress.add_task("Writing HTML", total=total)
        for cat, recs in data.items():
            for rec_name, vals in recs.items():
                kept = prune_record(vals, vt_enabled, opentip_enabled)
                if not kept:
                    continue

                row = {"Category": cat, "RecordName": rec_name, **kept}

                ot_status = ""
                det = None
                if vt_enabled:
                    det, tot, ratio = lookup_vt(kept["SHA-1"], vt_api_key)
                    row["VT_Detections"] = det
                    row["VT_TotalEngines"] = tot
                    row["VT_Ratio"] = ratio
                    if det and det > 0:
                        vt_hash = normalize_hash_for_lookup(kept["SHA-1"])
                        if vt_hash:
                            row["_vt_link"] = f"https://www.virustotal.com/gui/file/{vt_hash}"

                if opentip_enabled:
                    ot_status = lookup_opentip(kept["SHA-1"], ot_api_key)
                    row["OpenTIP_FileStatus"] = ot_status

                if only_detections and (vt_enabled or opentip_enabled):
                    if not is_detection_hit(vt_enabled, opentip_enabled, det, ot_status):
                        progress.advance(task)
                        continue

                row["_hit"] = is_detection_hit(vt_enabled, opentip_enabled, det, ot_status)
                rows.append(row)
                progress.advance(task)

    rows.sort(key=lambda r: r.get("RecordDate", ""))

    def display_value(key, value):
        if value is None:
            return ""
        if key == "IsOsComponent":
            return "Yes" if value else "No"
        return str(value)

    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    meta = [
        f"Records: {len(rows)}",
        f"VT: {'on' if vt_enabled else 'off'}",
        f"OpenTIP: {'on' if opentip_enabled else 'off'}",
        f"Only detections: {'yes' if only_detections else 'no'}",
        f"Generated: {generated}",
    ]

    with path.open("w", encoding="utf-8") as f:
        f.write("<!doctype html>\n")
        f.write("<html lang=\"en\">\n")
        f.write("<head>\n")
        f.write("<meta charset=\"utf-8\">\n")
        f.write("<title>Amcache Evil Hunter Report</title>\n")
        f.write("<style>\n")
        f.write(":root {\n")
        f.write("  --bg: #f5f1e7;\n")
        f.write("  --card: #ffffff;\n")
        f.write("  --text: #1f2328;\n")
        f.write("  --muted: #4b5563;\n")
        f.write("  --accent: #1d4ed8;\n")
        f.write("  --danger: #b42318;\n")
        f.write("  --border: #d0d7de;\n")
        f.write("}\n")
        f.write("body {\n")
        f.write("  margin: 0;\n")
        f.write("  padding: 32px 24px 48px;\n")
        f.write("  font-family: \"Palatino Linotype\", Palatino, \"Book Antiqua\", serif;\n")
        f.write("  color: var(--text);\n")
        f.write("  background: linear-gradient(180deg, #fbf8f2 0%, #f0e7d8 100%);\n")
        f.write("}\n")
        f.write("h1 {\n")
        f.write("  margin: 0 0 8px;\n")
        f.write("  font-size: 28px;\n")
        f.write("  letter-spacing: 0.5px;\n")
        f.write("}\n")
        f.write(".meta {\n")
        f.write("  display: flex;\n")
        f.write("  flex-wrap: wrap;\n")
        f.write("  gap: 8px 16px;\n")
        f.write("  font-size: 14px;\n")
        f.write("  color: var(--muted);\n")
        f.write("  margin-bottom: 18px;\n")
        f.write("}\n")
        f.write(".card {\n")
        f.write("  background: var(--card);\n")
        f.write("  border: 1px solid var(--border);\n")
        f.write("  border-radius: 10px;\n")
        f.write("  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.08);\n")
        f.write("  overflow: auto;\n")
        f.write("}\n")
        f.write(".controls {\n")
        f.write("  display: flex;\n")
        f.write("  flex-wrap: wrap;\n")
        f.write("  gap: 12px 16px;\n")
        f.write("  align-items: center;\n")
        f.write("  margin: 18px 0 16px;\n")
        f.write("}\n")
        f.write(".controls label {\n")
        f.write("  font-size: 13px;\n")
        f.write("  color: var(--muted);\n")
        f.write("}\n")
        f.write(".controls input[type=\"text\"],\n")
        f.write(".controls select {\n")
        f.write("  padding: 8px 10px;\n")
        f.write("  border: 1px solid var(--border);\n")
        f.write("  border-radius: 8px;\n")
        f.write("  font-size: 13px;\n")
        f.write("  min-width: 180px;\n")
        f.write("  background: #fff;\n")
        f.write("}\n")
        f.write(".controls .count {\n")
        f.write("  margin-left: auto;\n")
        f.write("  font-size: 13px;\n")
        f.write("  color: var(--muted);\n")
        f.write("}\n")
        f.write("table {\n")
        f.write("  border-collapse: collapse;\n")
        f.write("  width: 100%;\n")
        f.write("  min-width: 1200px;\n")
        f.write("  font-size: 13px;\n")
        f.write("}\n")
        f.write("thead th {\n")
        f.write("  position: sticky;\n")
        f.write("  top: 0;\n")
        f.write("  background: #f9fafb;\n")
        f.write("  color: var(--muted);\n")
        f.write("  text-align: left;\n")
        f.write("  padding: 10px 12px;\n")
        f.write("  border-bottom: 1px solid var(--border);\n")
        f.write("  font-size: 12px;\n")
        f.write("  text-transform: uppercase;\n")
        f.write("  letter-spacing: 0.6px;\n")
        f.write("}\n")
        f.write("tbody td {\n")
        f.write("  padding: 10px 12px;\n")
        f.write("  border-bottom: 1px solid #ececec;\n")
        f.write("  vertical-align: top;\n")
        f.write("  word-break: break-word;\n")
        f.write("}\n")
        f.write("tbody tr:nth-child(even) {\n")
        f.write("  background: #fcfbf8;\n")
        f.write("}\n")
        f.write("tbody tr.hit {\n")
        f.write("  background: #fff1f1;\n")
        f.write("}\n")
        f.write("tbody tr.hit td:first-child {\n")
        f.write("  border-left: 4px solid var(--danger);\n")
        f.write("}\n")
        f.write("</style>\n")
        f.write("</head>\n")
        f.write("<body>\n")
        f.write("<h1>Amcache Evil Hunter Report</h1>\n")
        f.write("<div class=\"meta\">\n")
        for item in meta:
            f.write(f"<span>{html.escape(item)}</span>\n")
        f.write("</div>\n")
        f.write("<div class=\"controls\">\n")
        f.write("<label>Search\n")
        f.write("<input id=\"searchInput\" type=\"text\" placeholder=\"Name, path, hash, publisher\">\n")
        f.write("</label>\n")
        f.write("<label>\n")
        f.write("<input id=\"missingPublisher\" type=\"checkbox\">\n")
        f.write(" Missing publisher only\n")
        f.write("</label>\n")
        f.write("<label>Sort by\n")
        f.write("<select id=\"sortSelect\">\n")
        f.write("<option value=\"recorddate-asc\">RecordDate (oldest)</option>\n")
        f.write("<option value=\"recorddate-desc\">RecordDate (newest)</option>\n")
        f.write("<option value=\"size-desc\">Size (largest)</option>\n")
        f.write("<option value=\"size-asc\">Size (smallest)</option>\n")
        f.write("<option value=\"name-asc\">Name (A-Z)</option>\n")
        f.write("<option value=\"name-desc\">Name (Z-A)</option>\n")
        f.write("</select>\n")
        f.write("</label>\n")
        f.write("<span class=\"count\" id=\"rowCount\"></span>\n")
        f.write("</div>\n")
        f.write("<div class=\"card\">\n")
        f.write("<table>\n")
        f.write("<thead><tr>\n")
        for head in headers:
            f.write(f"<th>{html.escape(head)}</th>\n")
        f.write("</tr></thead>\n")
        f.write("<tbody>\n")
        for idx, row in enumerate(rows):
            row_class = "hit" if row.get("_hit") else ""
            publisher = (row.get("Publisher") or "").strip()
            size_val = row.get("Size")
            size_num = size_val if isinstance(size_val, int) else 0
            search_parts = [
                row.get("Name", ""),
                row.get("FilePath", ""),
                row.get("LowerCaseLongPath", ""),
                row.get("SHA-1", ""),
                row.get("Publisher", ""),
                row.get("ProductName", ""),
                row.get("OriginalFileName", ""),
                row.get("RecordName", ""),
            ]
            search_blob = " ".join(p for p in search_parts if p).lower()
            f.write(
                "<tr class=\"{cls}\" data-index=\"{idx}\" data-size=\"{size}\" "
                "data-name=\"{name}\" data-recorddate=\"{record_date}\" "
                "data-publisher=\"{publisher}\" data-search=\"{search}\">\n".format(
                    cls=row_class,
                    idx=idx,
                    size=size_num,
                    name=html.escape((row.get("Name") or "").lower()),
                    record_date=html.escape(row.get("RecordDate", "")),
                    publisher=html.escape(publisher.lower()),
                    search=html.escape(search_blob),
                )
            )
            for head in headers:
                value = display_value(head, row.get(head, ""))
                if head == "VT_Ratio" and row.get("_vt_link"):
                    link = html.escape(row["_vt_link"])
                    f.write(
                        f"<td><a href=\"{link}\" target=\"_blank\" rel=\"noreferrer\">"
                        f"{html.escape(value)}</a></td>\n"
                    )
                else:
                    f.write(f"<td>{html.escape(value)}</td>\n")
            f.write("</tr>\n")
        f.write("</tbody>\n")
        f.write("</table>\n")
        f.write("</div>\n")
        f.write("<script>\n")
        f.write("const rows = Array.from(document.querySelectorAll('tbody tr'));\n")
        f.write("const tbody = document.querySelector('tbody');\n")
        f.write("const searchInput = document.getElementById('searchInput');\n")
        f.write("const missingPublisher = document.getElementById('missingPublisher');\n")
        f.write("const sortSelect = document.getElementById('sortSelect');\n")
        f.write("const rowCount = document.getElementById('rowCount');\n")
        f.write("const totalRows = rows.length;\n")
        f.write("function compareRows(a, b, mode) {\n")
        f.write("  if (mode === 'size-desc' || mode === 'size-asc') {\n")
        f.write("    const av = parseInt(a.dataset.size || '0', 10);\n")
        f.write("    const bv = parseInt(b.dataset.size || '0', 10);\n")
        f.write("    return mode === 'size-desc' ? bv - av : av - bv;\n")
        f.write("  }\n")
        f.write("  if (mode === 'name-desc' || mode === 'name-asc') {\n")
        f.write("    const av = a.dataset.name || '';\n")
        f.write("    const bv = b.dataset.name || '';\n")
        f.write("    return mode === 'name-desc' ? bv.localeCompare(av) : av.localeCompare(bv);\n")
        f.write("  }\n")
        f.write("  const av = Date.parse(a.dataset.recorddate || '') || 0;\n")
        f.write("  const bv = Date.parse(b.dataset.recorddate || '') || 0;\n")
        f.write("  return mode === 'recorddate-desc' ? bv - av : av - bv;\n")
        f.write("}\n")
        f.write("function applyFilters() {\n")
        f.write("  const query = (searchInput.value || '').trim().toLowerCase();\n")
        f.write("  const missingOnly = missingPublisher.checked;\n")
        f.write("  const mode = sortSelect.value || 'recorddate-asc';\n")
        f.write("  const sorted = rows.slice().sort((a, b) => compareRows(a, b, mode));\n")
        f.write("  let visible = 0;\n")
        f.write("  sorted.forEach((row) => {\n")
        f.write("    const publisher = row.dataset.publisher || '';\n")
        f.write("    const search = row.dataset.search || '';\n")
        f.write("    const matchesMissing = !missingOnly || publisher === '';\n")
        f.write("    const matchesQuery = !query || search.includes(query);\n")
        f.write("    if (matchesMissing && matchesQuery) {\n")
        f.write("      row.style.display = '';\n")
        f.write("      visible += 1;\n")
        f.write("    } else {\n")
        f.write("      row.style.display = 'none';\n")
        f.write("    }\n")
        f.write("    tbody.appendChild(row);\n")
        f.write("  });\n")
        f.write("  rowCount.textContent = `${visible} / ${totalRows} shown`;\n")
        f.write("}\n")
        f.write("searchInput.addEventListener('input', applyFilters);\n")
        f.write("missingPublisher.addEventListener('change', applyFilters);\n")
        f.write("sortSelect.addEventListener('change', applyFilters);\n")
        f.write("applyFilters();\n")
        f.write("</script>\n")
        f.write("</body>\n")
        f.write("</html>\n")


def print_table(data, vt_enabled, opentip_enabled, vt_api_key=None, ot_api_key=None, only_detections=False):
    """Live-render a table of records; optionally filter detections."""
    any_printed = False
    rows_to_print = []

    def make_table():
        tbl = Table(show_header=True, header_style="bold cyan", expand=True)
        tbl.add_column("SHA-1", style="dim")
        tbl.add_column("Name")
        tbl.add_column("RecordDate", justify="center")
        tbl.add_column("OS?", justify="center")
        if vt_enabled:
            tbl.add_column("VT", justify="right")
        elif opentip_enabled:
            tbl.add_column("OT", justify="center")
        return tbl

    table = make_table()
    with Live(table, console=console, refresh_per_second=4) as live:
        for recs in data.values():
            for vals in recs.values():
                sha = vals.get("SHA-1")
                if not sha:
                    continue
                name = vals.get("Name", "")
                record_date_str = vals.get("RecordDate", "")
                os_flag = "Yes" if vals.get("IsOsComponent") else "No"

                style = None
                vt_cell = ""
                ot_cell = ""

                if vt_enabled:
                    det, _, vt_cell = lookup_vt(sha, vt_api_key)
                    if det and det > 0:
                        style = "bold red"
                    if only_detections and (det is None or det == 0):
                        continue

                elif opentip_enabled:
                    status = lookup_opentip(sha, ot_api_key)
                    ot_cell = status
                    if status.lower() == "malware":
                        style = "bold red"
                    if only_detections and status.lower() != "malware":
                        continue

                row = [sha, name, record_date_str, os_flag]
                if vt_enabled:
                    row.append(vt_cell)
                elif opentip_enabled:
                    row.append(ot_cell)

                rows_to_print.append((record_date_str, row, style))
                rows_to_print.sort(key=lambda t: t[0])

                table = make_table()
                for _, r, st in rows_to_print:
                    table.add_row(*r, style=st)
                live.update(table)
                any_printed = True

    if not any_printed:
        msg = "No entries found."
        if (vt_enabled or opentip_enabled) and only_detections:
            msg = "No entries with detections found."
        console.print(f"[bold red]{msg}[/]")
        sys.exit(1 if (vt_enabled or opentip_enabled) and only_detections else 0)


def main():
    """CLI entry point for amcache_evilhunter."""
    parser = argparse.ArgumentParser(
        description="AmCache-EvilHunter: parse and analyze a Windows Amcache.hve registry hive.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"AmCache-EvilHunter {VERSION} by Cristian Souza (cristianmsbr@gmail.com)"
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-v", "--vt", action="store_true",
                       help="Enable VirusTotal lookups (requires VT_API_KEY)")
    group.add_argument("--opentip", action="store_true",
                       help="Enable Kaspersky OpenTIP lookups (requires OPENTIP_API_KEY)")

    parser.add_argument('-V', '--version', action='version',
                        version=f"AmCache-EvilHunter {VERSION} by Cristian Souza")
    parser.add_argument("-i", "--input", type=Path, required=True, help="Path to Amcache.hve")
    parser.add_argument("--start", type=str, help="YYYY-MM-DD; only records on or after this date")
    parser.add_argument("--end", type=str, help="YYYY-MM-DD; only records on or before this date")
    parser.add_argument("--search", type=str, help="Comma-separated terms (case-insensitive)")
    parser.add_argument("--find-suspicious", action="store_true",
                        help="Filter only records matching known suspicious name patterns")
    parser.add_argument("--missing-publisher", action="store_true",
                        help="Filter only records with missing Publisher")
    parser.add_argument("--exclude-os", action="store_true", help="Only include non-OS-component files")
    parser.add_argument("--only-detections", action="store_true",
                        help="Show/save only files with ≥1 detection")
    parser.add_argument("--json", type=Path, help="Path to write JSON Lines")
    parser.add_argument("--csv", type=Path, help="Path to write CSV")
    parser.add_argument("--html", type=Path, help="Path to write HTML report")
    parser.add_argument("--show-table", action="store_true",
                        help="Render console table even when writing output files")
    parser.add_argument("--trim-sha1", action="store_true",
                        help="Trim leading zeros from SHA-1 values (legacy behavior)")
    args = parser.parse_args()

    vt_api_key = None
    ot_api_key = None
    if args.vt:
        vt_api_key = os.getenv("VT_API_KEY")
        if not vt_api_key:
            console.print("[bold red]Error:[/] VT_API_KEY environment variable not set", style="red")
            sys.exit(1)
        if not check_vt_connection(vt_api_key):
            sys.exit(1)
    if args.opentip:
        ot_api_key = os.getenv("OPENTIP_API_KEY")
        if not ot_api_key:
            console.print("[bold red]Error:[/] OPENTIP_API_KEY environment variable not set", style="red")
            sys.exit(1)

    # parse date filters
    start_dt = None
    end_dt = None
    if args.start:
        try:
            start_dt = datetime.strptime(args.start, "%Y-%m-%d")
        except ValueError:
            console.print("[bold red]Error:[/] --start must be YYYY-MM-DD", style="red")
            sys.exit(1)
    if args.end:
        try:
            end_dt = datetime.strptime(args.end, "%Y-%m-%d")
        except ValueError:
            console.print("[bold red]Error:[/] --end must be YYYY-MM-DD", style="red")
            sys.exit(1)
    if start_dt and end_dt and start_dt > end_dt:
        console.print("[bold red]Error:[/] --start must be on or before --end", style="red")
        sys.exit(1)

    # parse search terms
    search_terms = None
    if args.search:
        search_terms = [t.strip().lower() for t in args.search.split(",") if t.strip()]

    try:
        parser = AmcacheParser(args.input, start_dt, end_dt)
        data = parser.parse()
        normalize_data(data, trim_sha1=args.trim_sha1)

        if search_terms:
            filtered = {}
            for cat, recs in data.items():
                keep = {
                    rec: vals
                    for rec, vals in recs.items()
                    if any(term in vals.get("FilePath", "").lower() for term in search_terms)
                }
                if keep:
                    filtered[cat] = keep
            data = filtered

        # filter suspicious patterns
        if args.find_suspicious:
            data = find_suspicious(data)

        # filter suspicious publishers
        if args.missing_publisher:
            data = missing_publisher(data)

        if args.exclude_os:
            filtered = {}
            for cat, recs in data.items():
                keep = {rec: vals for rec, vals in recs.items() if not vals.get("IsOsComponent")}
                if keep:
                    filtered[cat] = keep
            data = filtered

        output_requested = bool(args.json or args.csv or args.html)
        if not output_requested or args.show_table:
            print_table(
                data,
                vt_enabled=args.vt,
                opentip_enabled=args.opentip,
                vt_api_key=vt_api_key,
                ot_api_key=ot_api_key,
                only_detections=args.only_detections
            )

        if args.json:
            write_json(args.json, data, args.vt, args.opentip, vt_api_key, ot_api_key, args.only_detections)
        if args.csv:
            write_csv(args.csv, data, args.vt, args.opentip, vt_api_key, ot_api_key, args.only_detections)
        if args.html:
            write_html(args.html, data, args.vt, args.opentip, vt_api_key, ot_api_key, args.only_detections)

    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/] {e}", style="red")
        sys.exit(1)
    except HTTPError as e:
        console.print(f"[bold red]HTTP error:[/] {e}", style="red")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Operation cancelled by user.[/]")
        sys.exit(0)
