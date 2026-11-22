"""Synthetic HTTP fixtures; these tests contain no COBB image data."""
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "acquire_firmware", Path(__file__).parents[1] / "tools/acquire_por007_firmware.py")
acquisition = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acquisition)


class FirmwareAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "analysis/sources").mkdir(parents=True)
        self.files = {name: ("synthetic:" + name).encode() for name in
                      ["MD5SUMS", "ap-app.img", "ap-data.img", "bootstream.img", "rootfs.img"]}
        self.manifest = (acquisition.VERSION + "\n" + "".join(
            hashlib.md5(data).hexdigest() + " *" + name + "\n"
            for name, data in self.files.items())).encode()
        self.files["version_v3.txt"] = self.manifest
        self.requests = []

    def response(self, url, **kwargs):
        self.requests.append(url)
        response = io.BytesIO(self.files[url.rsplit("/", 1)[1]])
        response.headers = {"Content-Type": "application/octet-stream"}
        return response

    def run_acquisition(self):
        with patch.object(acquisition, "ROOT", self.root), \
             patch.object(acquisition, "VERSION_SHA256", hashlib.sha256(self.manifest).hexdigest()), \
             patch.object(acquisition.urllib.request, "urlopen", self.response), \
             contextlib.redirect_stdout(io.StringIO()):
            acquisition.main()

    def test_download_and_idempotent_recheck(self):
        self.run_acquisition()
        destination = self.root / "samples/firmware/AP-POR-007" / acquisition.VERSION
        for name, data in self.files.items():
            self.assertEqual((destination / name).read_bytes(), data)
        evidence = self.root / "analysis/sources/por007_firmware_download.json"
        original = evidence.read_bytes()
        self.run_acquisition()
        self.assertEqual(evidence.read_bytes(), original)
        self.assertEqual(len(self.requests), 7)  # First manifest + five files, then manifest only.

    def test_bad_download_never_becomes_final_file(self):
        self.files["ap-app.img"] = b"damaged synthetic response"
        with self.assertRaisesRegex(ValueError, "Downloaded hash mismatch"):
            self.run_acquisition()
        destination = self.root / "samples/firmware/AP-POR-007" / acquisition.VERSION
        self.assertFalse((destination / "ap-app.img").exists())
        self.assertTrue((destination / "ap-app.img.part").exists())

    def test_existing_conflict_is_preserved(self):
        self.run_acquisition()
        target = self.root / "samples/firmware/AP-POR-007" / acquisition.VERSION / "ap-app.img"
        target.write_bytes(b"unrelated local content")
        with self.assertRaisesRegex(ValueError, "Existing file mismatch"):
            self.run_acquisition()
        self.assertEqual(target.read_bytes(), b"unrelated local content")


if __name__ == "__main__":
    unittest.main()
