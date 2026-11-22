"""Porsche identity reads recovered from the verified POR-007 ARM library."""
from datetime import datetime, timezone

from j2534 import Device, DiagnosticError


LIBRARY_SHA256 = "7598720b7a15d38c1d97a9c78d6d604fa15e6d13085fb07fafcae0f7786ef700"
# Only these observed identification requests are exposed by the tool.
PROFILES = {
    "ecu": {"family": "SDI9_981", "tx": 0x7E0, "rx": 0x7E8,
            "requests": (b"\x10\x89", b"\x1a\x95", b"\x10\x81")},
    "pdk": {"family": "PDK_991", "tx": 0x71E, "rx": 0x788,
            "requests": (b"\x10\x81", b"\x10\x89", b"\x22\xf0\x03", b"\x1a\x8a")},
}


def identity_text(data):
    text = data.rstrip(b"\x00 \t\r\n")
    if not text or len(text) > 128 or any(not 0x21 <= c <= 0x7E for c in text):
        raise ValueError("控制器标识不是有效的可打印 ASCII 文本；原始响应已保留")
    return text.decode("ascii")


def read_identity(device, target, trace):
    profile = PROFILES[target]
    device.connect_isotp(500000, [(profile["tx"], profile["rx"])])
    parts = []
    for request in profile["requests"]:
        prefix = bytes([request[0] + 0x40]) + request[1:]
        response = device.exchange(profile["tx"], profile["rx"], request, prefix, trace)
        if request[0] != 0x10:
            parts.append(identity_text(response[len(prefix):]))
    return "_".join(parts)


def read_recovery_identity(device, target, expected_software, trace):
    """Source IdentifyECU fallback, with liveness and programming access kept separate."""
    profile = PROFILES[target]
    device.connect_isotp(500000, [(profile["tx"], profile["rx"])])
    parts = []
    for request in profile["requests"]:
        prefix = bytes([request[0] + 0x40]) + request[1:]
        try:
            response = device.exchange(profile["tx"], profile["rx"], request, prefix, trace)
        except (TimeoutError, DiagnosticError) as error:
            if request[0] == 0x10 or (isinstance(error, DiagnosticError) and error.nrc not in (0x22, 0x31)):
                raise
            return {"state": "application-unidentified", "software": None, "bootloader_verified": False,
                    "reason": "Identification unavailable after a confirmed diagnostic session"}
        if request[0] != 0x10:
            value = identity_text(response[len(prefix):])
            if value in ("recovery_mode", "RECOVERY_MODE"):
                return {"state": "application-unidentified", "software": None, "bootloader_verified": False,
                        "reason": "Controller returned recovery marker"}
            if value != expected_software.split("_")[len(parts)]:
                raise ValueError("恢复目标的已读软件标识与原任务不符；未进入编程")
            parts.append(value)
    software = "_".join(parts)
    if software != expected_software:
        raise ValueError("恢复目标的软件标识与原任务不符；未进入编程")
    return {"state": "identified", "software": software, "bootloader_verified": False}


def identify(path, target):
    if target not in PROFILES:
        raise ValueError("请选择 ecu 或 pdk")
    profile = PROFILES[target]
    result = {"created_utc": datetime.now(timezone.utc).isoformat(), "ok": False,
              "operation": "porsche-identification", "target": target,
              "family_candidate": profile["family"], "baud": 500000,
              "tx_id": f"0x{profile['tx']:03x}", "rx_id": f"0x{profile['rx']:03x}",
              "protocol_source_sha256": LIBRARY_SHA256, "transactions": [],
              "vehicle_flash_verified": False, "closed": False}
    device = None
    try:
        device = Device(path)
        with device:
            result["adapter"] = device.info()
            result["software_revision"] = read_identity(device, target, result["transactions"])
        result["closed"] = True
        result["ok"] = True
    except (OSError, ValueError) as exc:
        result["error"] = str(exc)
    result["closed"] = bool(device and device.closed)
    return result
