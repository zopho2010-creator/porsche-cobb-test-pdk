"""Exercise the PDK backup and recovery reference model using synthetic data."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile


# Synthetic segment labels and block size for the in-memory model.
PLANS = {"pdk": {"segments": (1, 2, 3), "chunk": 256}}
SCOPE = "synthetic-application-segments-only"


def digest(data):
    return hashlib.sha256(data).hexdigest()


class SimulatedFailure(ValueError):
    pass


class ControllerModel:
    """A semantic reference model, not a 981 ECU emulator or a J2534 implementation."""
    def __init__(self, target):
        self.target = target
        self.plan = PLANS[target]
        self.identity = {"target": target, "hw": "SIM-HW-1", "sw": "SIM-SW-1", "vin": "SIM-VEHICLE-A"}
        self.memory = {hex(s): bytes((i + s) % 256 for i in range(1033)) for s in self.plan["segments"]}
        self.events = []
        self.recovery_required = False
        self.bootloader_available = True

    def hashes(self):
        return {s: digest(data) for s, data in self.memory.items()}

    def backup(self):
        return {"scope": SCOPE, "synthetic": True, "identity": dict(self.identity),
                "segments": {s: {"length": len(data), "sha256": digest(data), "data_hex": data.hex()}
                             for s, data in self.memory.items()}}

    def program(self, package, fault=None, unlocked=True):
        if not package or package.get("scope") != SCOPE or package.get("synthetic") is not True:
            raise SimulatedFailure("missing-or-unsupported-backup-scope")
        if package.get("identity") != self.identity:
            raise SimulatedFailure("identity-mismatch")
        records = package.get("segments", {})
        if set(records) != set(self.memory):
            raise SimulatedFailure("incomplete-segment-set")
        prepared = {}
        for segment, current in self.memory.items():
            record = records[segment]
            try:
                data = bytes.fromhex(record["data_hex"])
            except (KeyError, TypeError, ValueError) as exc:
                raise SimulatedFailure("invalid-backup-encoding") from exc
            if len(data) != len(current) or record.get("length") != len(data) or record.get("sha256") != digest(data):
                raise SimulatedFailure("backup-integrity-failed")
            prepared[segment] = data
        if not self.bootloader_available:
            raise SimulatedFailure("bootloader-unreachable-no-obd-recovery")
        if not unlocked:
            self.events.append({"phase": "security-rejected"})
            raise SimulatedFailure("security-denied")
        self.events.append({"phase": "security-and-checksums-assumed"})
        self.recovery_required = True
        for number in self.plan["segments"]:
            segment = hex(number)
            data = prepared[segment]
            self.events.append({"phase": "erase", "segment": segment})
            self.memory[segment] = bytes([255]) * len(data)
            if fault == ("after-erase", segment):
                raise SimulatedFailure("power-loss-after-erase")
            for offset in range(0, len(data), self.plan["chunk"]):
                block = data[offset:offset + self.plan["chunk"]]
                current = self.memory[segment]
                self.memory[segment] = current[:offset] + block + current[offset + len(block):]
                self.events.append({"phase": "write", "segment": segment, "offset": offset, "length": len(block)})
                if offset == 0 and fault in (("during-write", segment), ("lost-write-ack", segment)):
                    raise SimulatedFailure("write-outcome-uncertain-no-auto-retry")
            self.events.append({"phase": "transfer-exit", "segment": segment})
            if fault == ("corrupt-write", segment):
                self.memory[segment] = bytes([data[0] ^ 1]) + data[1:]
            if self.memory[segment] != data:
                raise SimulatedFailure("post-write-verification-failed")
            self.events.append({"phase": "verify", "segment": segment})
            if fault == ("after-verify", segment):
                raise SimulatedFailure("disconnect-after-verify")
        self.events.append({"phase": "reset"})
        if fault == ("reset", None):
            raise SimulatedFailure("reset-unconfirmed")
        self.recovery_required = False
        self.events.append({"phase": "complete"})


def changed_image(backup):
    package = deepcopy(backup)
    for record in package["segments"].values():
        data = bytes(byte ^ 0x5a for byte in bytes.fromhex(record["data_hex"]))
        record.update(data_hex=data.hex(), sha256=digest(data))
    return package


def expect_failure(operation, message):
    try:
        operation()
    except SimulatedFailure as exc:
        assert str(exc) == message, (str(exc), message)
        return str(exc)
    raise AssertionError("Expected failure was incorrectly reported as success")


def model_cases():
    rows = []
    for target in PLANS:
        controller = ControllerModel(target)
        original = controller.hashes()
        backup = controller.backup()
        image = changed_image(backup)
        with tempfile.TemporaryDirectory(prefix="981 simulation ") as folder:
            path = Path(folder) / "synthetic-backup.json"
            with path.open("x", encoding="utf-8") as stream:
                json.dump(backup, stream)
            file_hash = digest(path.read_bytes())
            controller.program(image)
            assert controller.hashes() != original and not controller.recovery_required
            flash_trace = list(controller.events)
            assert [int(e["segment"], 16) for e in flash_trace if e["phase"] == "erase"] == list(PLANS[target]["segments"])
            assert all(e["length"] <= PLANS[target]["chunk"] for e in flash_trace if e["phase"] == "write")
            # Reopen the persisted synthetic backup, rather than restoring a still-live Python snapshot.
            loaded = json.loads(path.read_text(encoding="utf-8"))
            controller.program(loaded)
            assert controller.hashes() == original and digest(path.read_bytes()) == file_hash
            rows.append({"target": target, "scenario": "backup-flash-restore-roundtrip", "passed": True,
                         "backup_reopened_from_disk": True, "restored_hashes": controller.hashes(), "flash_trace": flash_trace})
            try:
                with path.open("x", encoding="utf-8") as stream:
                    json.dump(image, stream)
            except FileExistsError:
                assert digest(path.read_bytes()) == file_hash
            else:
                raise AssertionError("Existing backup was overwritten")
            rows.append({"target": target, "scenario": "preserve-existing-backup", "passed": True})
        invalid = []
        for field in ("target", "hw", "sw", "vin"):
            wrong = deepcopy(backup)
            wrong["identity"][field] = "SIM-WRONG"
            invalid.append(("wrong-" + field, wrong, "identity-mismatch"))
        for kind in ("missing-segment", "truncated-data", "tampered-hash", "full-controller-scope"):
            wrong = deepcopy(backup)
            first = next(iter(wrong["segments"]))
            if kind == "missing-segment":
                del wrong["segments"][first]
                error = "incomplete-segment-set"
            elif kind == "full-controller-scope":
                wrong["scope"] = "full-flash-eeprom-immo"
                error = "missing-or-unsupported-backup-scope"
            else:
                wrong["segments"][first]["data_hex" if kind == "truncated-data" else "sha256"] = "00"
                error = "backup-integrity-failed"
            invalid.append((kind, wrong, error))
        invalid.append(("lost-backup", None, "missing-or-unsupported-backup-scope"))
        for name, package, error in invalid:
            controller = ControllerModel(target)
            before = controller.hashes()
            observed = expect_failure(lambda: controller.program(package), error)
            assert controller.hashes() == before and controller.events == []
            rows.append({"target": target, "scenario": name, "passed": True, "blocked_before_erase": True, "observed": observed})
        controller = ControllerModel(target)
        expect_failure(lambda: controller.program(image, unlocked=False), "security-denied")
        assert not any(e["phase"] == "erase" for e in controller.events)
        rows.append({"target": target, "scenario": "security-denied", "passed": True, "blocked_before_erase": True})
        faults = [(phase, hex(segment)) for segment in PLANS[target]["segments"]
                  for phase in ("after-erase", "during-write", "after-verify")]
        faults.extend([("lost-write-ack", hex(PLANS[target]["segments"][0])),
                       ("corrupt-write", hex(PLANS[target]["segments"][0])), ("reset", None)])
        for fault in faults:
            controller = ControllerModel(target)
            before = controller.hashes()
            try:
                controller.program(image, fault=fault)
            except SimulatedFailure as exc:
                observed = str(exc)
            else:
                raise AssertionError("Injected failure was ignored")
            assert controller.recovery_required and controller.hashes() != before
            failed_trace = list(controller.events)
            controller.program(deepcopy(backup))
            assert not controller.recovery_required and controller.hashes() == before
            rows.append({"target": target, "scenario": "fault-" + fault[0], "segment": fault[1],
                         "passed": True, "observed": observed, "failure_trace": failed_trace,
                         "recovery": "model-full-rewrite-with-presumed-bootloader-and-matching-backup", "restored_exactly": True})
        controller = ControllerModel(target)
        first = hex(PLANS[target]["segments"][0])
        expect_failure(lambda: controller.program(image, fault=("after-erase", first)), "power-loss-after-erase")
        controller.bootloader_available = False
        before = controller.hashes()
        observed = expect_failure(lambda: controller.program(backup), "bootloader-unreachable-no-obd-recovery")
        assert controller.recovery_required and controller.hashes() == before
        rows.append({"target": target, "scenario": "bootloader-unreachable", "passed": True,
                     "observed": observed, "recovered": False})
    return rows


if __name__ == "__main__":
    results = model_cases()
    print(f"{len(results)} synthetic PDK backup, write and recovery scenarios passed.")
