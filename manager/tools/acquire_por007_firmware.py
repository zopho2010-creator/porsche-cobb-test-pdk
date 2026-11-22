"""Download the public POR-007 AP update; never executes or decrypts images."""
from pathlib import Path
import datetime
import hashlib
import json
import re
import time
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
BASE = "http://www.accessecu.com/support/accessport/AP-POR-007/"
VERSION = "1.8.0.0-29445"
VERSION_SHA256 = "267de9291ddb731e8c51730aabc0dea2401f59d6affbe3ab91c3dbd19e5d2005"


def main():
    destination = ROOT / "samples" / "firmware" / "AP-POR-007" / VERSION
    destination.mkdir(parents=True, exist_ok=True)
    # Refuse junctions/symlinks before writing into a sample directory.
    for parent in [destination, *destination.parents]:
        if parent.is_symlink() or parent.is_junction():
            raise ValueError(f"Linked destination: {parent}")
        if parent == ROOT:
            break
    with urllib.request.urlopen(BASE + "version_v3.txt", timeout=60) as response:
        manifest = response.read()
    if hashlib.sha256(manifest).hexdigest() != VERSION_SHA256:
        raise ValueError("Public version changed")
    lines = manifest.decode("ascii").splitlines()
    if lines[0] != VERSION:
        raise ValueError("Unexpected version")
    expected = {}
    for line in lines[1:]:
        match = re.fullmatch(r"([0-9a-f]{32}) \*([A-Za-z0-9.-]+)", line)
        if not match:
            raise ValueError(f"Unexpected manifest row: {line!r}")
        digest, filename = match.groups()
        if filename in expected:
            raise ValueError(f"Duplicate filename: {filename}")
        expected[filename] = digest
    if set(expected) != {"MD5SUMS", "ap-app.img", "ap-data.img", "bootstream.img", "rootfs.img"}:
        raise ValueError("Unexpected file set")
    records = []
    for filename, expected_md5 in expected.items():
        target = destination / filename
        if target.is_symlink() or target.is_junction():
            raise ValueError(f"Linked target: {target}")
        url = BASE + VERSION + "/" + filename
        headers = None
        started = time.monotonic()
        if target.exists():
            data = target.read_bytes()
            if hashlib.md5(data).hexdigest() != expected_md5:
                raise ValueError(f"Existing file mismatch: {target}")
            elapsed = None
        else:
            temporary = target.with_suffix(target.suffix + ".part")
            if temporary.exists():
                raise FileExistsError(temporary)
            with urllib.request.urlopen(url, timeout=90) as response, temporary.open("xb") as output:
                headers = dict(response.headers)
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
            data = temporary.read_bytes()
            if hashlib.md5(data).hexdigest() != expected_md5:
                raise ValueError(f"Downloaded hash mismatch: {temporary}")
            temporary.rename(target)
            elapsed = round(time.monotonic() - started, 3)
        record = dict(filename=filename, url=url, bytes=len(data), md5=expected_md5,
                      sha256=hashlib.sha256(data).hexdigest(), seconds=elapsed, headers=headers)
        records.append(record)
        print(json.dumps({k: record[k] for k in ("filename", "bytes", "sha256", "seconds")}), flush=True)
    version_file = destination / "version_v3.txt"
    if version_file.is_symlink() or version_file.is_junction():
        raise ValueError(f"Linked version manifest: {version_file}")
    if version_file.exists():
        if version_file.read_bytes() != manifest:
            raise ValueError(f"Existing version manifest mismatch: {version_file}")
    else:
        version_file.write_bytes(manifest)
    metadata = dict(retrieved_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    manifest_url=BASE + "version_v3.txt", manifest_sha256=VERSION_SHA256,
                    version=VERSION, files=records,
                    integrity_limit="MD5 matches anonymous HTTP manifest; publisher authenticity is not cryptographically proven.")
    evidence = ROOT / "analysis" / "sources" / "por007_firmware_download.json"
    # Preserve the original download timing/headers on an idempotency check.
    if not evidence.exists():
        evidence.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print("All five downloads match the pinned public version manifest.")


if __name__ == "__main__":
    main()
