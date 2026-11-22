import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

MAIN = Path(__file__).resolve().parents[1] / "tools/manager_analyzer/main.py"
spec = importlib.util.spec_from_file_location("analyzer", MAIN)
analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyzer)


def fixture_pe(directory_count=16):
    """Build inert PE bytes with export, import, delay-import and resource tables."""
    data = bytearray(0x1200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14c, 1, 0, 0, 0, 224, 0x2102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10b)
    for offset, value in ((28, 0x400000), (32, 0x1000), (36, 0x200),
                          (56, 0x2000), (60, 0x200), (92, directory_count)):
        struct.pack_into("<I", data, optional + offset, value)
    struct.pack_into("<H", data, optional + 68, 3)
    section = optional + 224
    struct.pack_into("<8sIIIIIIHHI", data, section, b".rdata\0\0", 0x1000,
                     0x1000, 0x1000, 0x200, 0, 0, 0, 0, 0x40000040)
    for index, rva, size in ((0, 0x1000, 0xa0), (1, 0x1100, 40),
                             (2, 0x1300, 0x84), (13, 0x1200, 64)):
        struct.pack_into("<II", data, optional + 96 + index * 8, rva, size)

    def put(rva, payload):
        offset = rva - 0x1000 + 0x200
        data[offset:offset + len(payload)] = payload

    put(0x1000, struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, 0x1090,
                            7, 2, 1, 0x1040, 0x1050, 0x1060))
    put(0x1040, struct.pack("<II", 0x1800, 0x1070))
    put(0x1050, struct.pack("<I", 0x1080))
    put(0x1060, struct.pack("<H", 1))
    put(0x1070, b"other.Target\0")
    put(0x1080, b"Forwarded\0")
    put(0x1090, b"fixture.dll\0")
    put(0x1100, struct.pack("<IIIII", 0x1140, 0, 0, 0x1180, 0x1160))
    put(0x1140, struct.pack("<III", 0x11a0, 0x80000005, 0))
    put(0x1160, struct.pack("<III", 0x11a0, 0x80000005, 0))
    put(0x1180, b"KERNEL32.dll\0")
    put(0x11a0, b"\0\0NamedImport\0")
    put(0x1200, struct.pack("<IIIIIIII", 1, 0x1280, 0, 0x1260, 0x1240, 0, 0, 0))
    put(0x1240, struct.pack("<III", 0x12a0, 0x80000009, 0))
    put(0x1260, struct.pack("<III", 0x12a0, 0x80000009, 0))
    put(0x1280, b"USER32.dll\0")
    put(0x12a0, b"\0\0DelayedImport\0")
    for rva, identifier, child in ((0x1300, 10, 0x80000020),
                                   (0x1320, 1, 0x80000040), (0x1340, 1033, 0x60)):
        put(rva + 12, struct.pack("<HHII", 0, 1, identifier, child))
    put(0x1360, struct.pack("<IIII", 0x1380, 4, 0, 0))
    put(0x1380, b"DATA")
    return bytes(data)


class AnalyzerTests(unittest.TestCase):
    def test_strings_and_categories(self):
        data = b"\xffUSB VID_1a84\x00\xff" + "PDK firmware".encode("utf-16le") + b"\0\0"
        rows = list(analyzer.strings(data))
        self.assertTrue(any(r["offset"] == 1 and "usb" in r["categories"] for r in rows))
        self.assertTrue(any(r["value"] == "PDK firmware" and r["encoding"] == "utf-16le" for r in rows))
        self.assertEqual(analyzer.features(Path("a.bin"), b"PK\x03\x04")[0]["type"], "ZIP")

    def test_utf16_at_both_byte_alignments(self):
        for prefix in (b"\xff", b"\xff\xff"):
            rows = list(analyzer.strings(prefix + "PDK firmware".encode("utf-16le") + b"\0\0"))
            wide = [r for r in rows if r["encoding"] == "utf-16le"]
            self.assertEqual(len(wide), 1)
            self.assertEqual(wide[0]["offset"], len(prefix))
            self.assertEqual(wide[0]["value"], "PDK firmware")

    def test_pe_tables_and_short_directory_table(self):
        with analyzer.pefile.PE(data=fixture_pe()) as pe:
            metadata = analyzer.pe_metadata(pe)
        self.assertEqual(metadata["imports"][0]["dll"], "KERNEL32.dll")
        self.assertEqual(metadata["imports"][0]["symbols"], [
            {"name": "NamedImport", "ordinal": None, "iat_va": "0x401160"},
            {"name": None, "ordinal": 5, "iat_va": "0x401164"}])
        self.assertEqual(metadata["delay_imports"][0]["symbols"], [
            {"name": "DelayedImport", "ordinal": None, "iat_va": "0x401260"},
            {"name": None, "ordinal": 9, "iat_va": "0x401264"}])
        self.assertEqual(metadata["exports"], [
            {"name": "Forwarded", "ordinal": 8, "rva": "0x1070", "forwarder": "other.Target"},
            {"name": None, "ordinal": 7, "rva": "0x1800", "forwarder": None}])
        self.assertEqual(metadata["resources"], [{"path": ["10", "1", "1033"], "rva": "0x1380", "size": 4}])
        with analyzer.pefile.PE(data=fixture_pe(directory_count=0)) as pe:
            self.assertEqual(analyzer.pe_metadata(pe)["certificate_table_size"], 0)

    def test_scan_and_report_space_path_malformed_pe(self):
        with tempfile.TemporaryDirectory(prefix="manager test ") as temporary:
            base = Path(temporary)
            samples = base / "input files"
            samples.mkdir()
            payload = b"MZ malformed firmware"
            (samples / "broken.exe").write_bytes(payload)
            (samples / "USB.ini").write_text("USB\\VID_1a84&PID_0120", encoding="utf-8")
            (samples / "tables.dll").write_bytes(fixture_pe())
            # A real Python launcher exercises imports, resources and address mapping.
            (samples / "python.exe").write_bytes(Path(sys.executable).read_bytes())
            out = base / "scan output"
            subprocess.run([sys.executable, str(MAIN), "scan", str(samples), "--output", str(out)], check=True, capture_output=True)
            data = json.loads((out / "scan.json").read_text())
            self.assertEqual(len(data["files"]), 4)
            broken = next(f for f in data["files"] if f["path"] == "broken.exe")
            self.assertEqual(broken["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertTrue(broken["errors"])
            valid = next(f for f in data["files"] if f["path"] == "python.exe")
            self.assertTrue(valid["pe"]["imports"])
            edges = json.loads((out / "dependencies/dependencies.json").read_text())
            self.assertIn({"source": "tables.dll", "target": "USER32.dll", "kind": "delay_imports"}, edges)
            table_strings = json.loads((out / "strings/tables.dll.json").read_text())
            self.assertTrue(any(s["value"] == "NamedImport" and s.get("va") == "0x4011a2" for s in table_strings))
            subprocess.run([sys.executable, str(MAIN), "report", str(out), "--output", str(base / "reports")], check=True, capture_output=True)
            self.assertIn("flowchart", (base / "reports/dependencies.mmd").read_text())
            with self.assertRaises(ValueError):
                analyzer.scan(samples, samples / "generated")


if __name__ == "__main__":
    unittest.main()
