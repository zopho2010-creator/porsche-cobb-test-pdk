"""Offline inventory and PE triage; never executes or modifies samples."""
import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parents[2]
CATEGORIES = {
    "usb": r"usb|vid_[0-9a-f]+|pid_[0-9a-f]+|winusb|libusb|ftd2|setupdi",
    "firmware": r"firmware|bootloader|recovery|\.apf\b|upgrade",
    "vehicle": r"\becu\b|\btcu\b|\bpdk\b|porsche|\b981\b|\bcan\b|iso.?tp|\buds\b|calibration",
    "map_file": r"\bmap\b|\.ptm\b|\.map\b|datalog|checksum|crc|inflate|deflate|compress",
    "network": r"https?://|ftp://|download|update|curl|ssl|tls",
    "logging": r"\blog\b|\.log\b|error|failed|debug|diagnostic",
}
PATTERNS = {k: re.compile(v, re.I) for k, v in CATEGORIES.items()}


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def strings(data):
    """Preserve byte offsets, including UTF-16LE strings at odd offsets."""
    for encoding, pattern in (("ascii", rb"[\x20-\x7e]{4,}"),
                              ("utf-16le", rb"(?:[\x20-\x7e]\x00){4,}")):
        for match in re.finditer(pattern, data):
            value = match.group().decode(encoding)
            yield {"offset": match.start(), "encoding": encoding, "value": value,
                   "categories": [k for k, p in PATTERNS.items() if p.search(value)]}


def text(value):
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def pe_metadata(pe):
    result = {
        "machine": hex(pe.FILE_HEADER.Machine),
        "architecture": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "unknown"),
        "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "timestamp_raw": pe.FILE_HEADER.TimeDateStamp,
        "timestamp_utc": dt.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, dt.timezone.utc).isoformat(),
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "sections": [{"name": text(s.Name.rstrip(b"\0")), "rva": hex(s.VirtualAddress),
                      "raw_offset": s.PointerToRawData, "raw_size": s.SizeOfRawData,
                      "virtual_size": s.Misc_VirtualSize, "entropy": s.get_entropy(),
                      "characteristics": hex(s.Characteristics)} for s in pe.sections],
        "imports": [], "delay_imports": [], "exports": [], "version": {}, "resources": [],
        "certificate_table_size": (pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
                                   if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 else 0),
        "overlay_offset": pe.get_overlay_data_start_offset(),
        "warnings": pe.get_warnings(),
    }
    for attribute, key in (("DIRECTORY_ENTRY_IMPORT", "imports"),
                           ("DIRECTORY_ENTRY_DELAY_IMPORT", "delay_imports")):
        for entry in getattr(pe, attribute, []):
            result[key].append({"dll": text(entry.dll), "symbols": [
                {"name": text(i.name) if i.name else None, "ordinal": i.ordinal,
                 "iat_va": hex(i.address)} for i in entry.imports]})
    for e in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
        result["exports"].append({"name": text(e.name) if e.name else None,
                                  "ordinal": e.ordinal, "rva": hex(e.address),
                                  "forwarder": text(e.forwarder) if e.forwarder else None})
    for group in getattr(pe, "FileInfo", []):
        for info in group:
            for table in getattr(info, "StringTable", []):
                result["version"].update({text(k): text(v) for k, v in table.entries.items()})

    def resources(directory, names=()):
        for entry in directory.entries:
            label = str(entry.name) if entry.name else str(entry.id)
            if hasattr(entry, "directory"):
                resources(entry.directory, names + (label,))
            elif hasattr(entry, "data"):
                d = entry.data.struct
                result["resources"].append({"path": list(names + (label,)),
                                            "rva": hex(d.OffsetToData), "size": d.Size})
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        resources(pe.DIRECTORY_ENTRY_RESOURCE)
    return result


def features(path, data):
    found = []
    for magic, name in ((b"PK\x03\x04", "ZIP"), (b"\x1f\x8b\x08", "gzip"),
                        (b"7z\xbc\xaf\x27\x1c", "7z"), (b"MSCF", "CAB"),
                        (b"\x89PNG\r\n\x1a\n", "PNG")):
        offset = data.find(magic)
        if offset >= 0:
            found.append({"type": name, "offset": offset, "status": "magic candidate only"})
    if b"NullsoftInst" in data[:65536]:
        found.append({"type": "NSIS", "status": "installer signature"})
    if path.suffix.lower() in (".bin", ".fw", ".rom", ".hex", ".apf", ".ptm", ".map"):
        found.append({"type": "firmware_or_map_candidate", "status": "extension only"})
    return found


def scan(target, output):
    target = target.resolve(strict=True)
    output = output.resolve()
    if target.is_dir() and (output == target or target in output.parents):
        raise ValueError("Output must be outside the input tree to avoid scanning generated reports")
    paths = [target] if target.is_file() else sorted(p for p in target.rglob("*") if p.is_file() and not p.is_symlink())
    inventory, dependencies = [], []
    for path in paths:
        relative = path.name if target.is_file() else path.relative_to(target).as_posix()
        row = {"path": relative, "size": None, "sha256": None, "errors": []}
        pe = None
        try:
            data = path.read_bytes()
            row.update(size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                       extension=path.suffix.lower(), features=features(path, data))
            artifact = Path(relative + ".json")
            if data.startswith(b"MZ"):
                try:
                    pe = pefile.PE(data=data)
                    row["pe"] = pe_metadata(pe)
                    write_json(output / "pe_metadata" / artifact, row["pe"])
                    for kind in ("imports", "delay_imports"):
                        dependencies.extend({"source": relative, "target": i["dll"], "kind": kind}
                                            for i in row["pe"][kind])
                except (pefile.PEFormatError, ValueError, OverflowError) as exc:
                    row["errors"].append("PE: " + str(exc))
            extracted = list(strings(data))
            if pe:
                for entry in extracted:
                    for section in pe.sections:
                        if section.PointerToRawData <= entry["offset"] < section.PointerToRawData + section.SizeOfRawData:
                            entry["va"] = hex(pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + entry["offset"] - section.PointerToRawData)
                            break
            row["string_count"] = len(extracted)
            write_json(output / "strings" / artifact, extracted)
        except OSError as exc:
            row["errors"].append(str(exc))
        finally:
            if pe:
                pe.close()
        inventory.append(row)
    report = {"schema_version": 1, "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "target": str(target), "files": inventory,
              "limitations": ["Static evidence only; string/magic hits do not prove implementation",
                              "Archive members require separate extraction; no sample is executed",
                              "Authenticode trust must be checked separately on Windows"]}
    write_json(output / "scan.json", report)
    write_json(output / "dependencies" / "dependencies.json", dependencies)
    return output / "scan.json"


def report(source, output):
    if source.is_dir():
        source = source / "scan.json"
    data = json.loads(source.read_text(encoding="utf-8"))
    rows = ["# Static inventory", "", "Generated from scan.json. All PE facts are static; feature hints require verification.",
            "", "| File | Bytes | Architecture | SHA-256 | Errors |", "|---|---:|---|---|---|"]
    for f in data["files"]:
        name = f["path"].replace("|", "&#124;")
        rows.append(f"| {name} | {f['size']} | {f.get('pe', {}).get('architecture', '-')} | {f['sha256']} | {len(f['errors'])} |")
    output.mkdir(parents=True, exist_ok=True)
    (output / "inventory_generated.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
    edges = json.loads((source.parent / "dependencies" / "dependencies.json").read_text(encoding="utf-8"))
    nodes = sorted({e[k] for e in edges for k in ("source", "target")})
    ids = {n: f"n{i}" for i, n in enumerate(nodes)}
    graph = ["flowchart LR"]
    graph.extend(f'  {ids[n]}["{n.replace(chr(34), chr(39))}"]' for n in nodes)
    graph.extend(f"  {ids[e['source']]} -->|{e['kind']}| {ids[e['target']]}" for e in edges)
    (output / "dependencies.mmd").write_text("\n".join(graph) + "\n", encoding="utf-8")
    return output / "inventory_generated.md"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("scan", "report"))
    parser.add_argument("path", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "scan":
            result = scan(args.path, args.output or ROOT / "analysis")
        else:
            result = report(args.path, args.output or ROOT / "reports")
        print(result)
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
