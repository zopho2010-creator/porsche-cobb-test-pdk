"""J2534-1 v04.04 probes and bounded ISO15765 diagnostic exchanges."""
import ctypes as C
import hashlib
from pathlib import Path
import platform
import re
import struct
import sys
import time


U32 = C.c_uint32
P32 = C.POINTER(U32)
ISO15765 = 6
FRAME_PAD = 0x40


class Message(C.Structure):
    _fields_ = [(name, U32) for name in
                ("ProtocolID", "RxStatus", "TxFlags", "Timestamp", "DataSize", "ExtraDataIndex")] + [
                    ("Data", C.c_ubyte * 4128)]


assert C.sizeof(Message) == 4152 and Message.Data.offset == 24


def pe_architecture(path):
    try:
        with Path(path).open("rb") as stream:
            header = stream.read(64)
            if len(header) < 64 or header[:2] != b"MZ":
                return "unknown"
            stream.seek(struct.unpack_from("<I", header, 60)[0])
            pe = stream.read(6)
        if len(pe) != 6 or pe[:4] != b"PE\0\0":
            return "unknown"
        return {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}.get(
            struct.unpack_from("<H", pe, 4)[0], "unknown")
    except OSError as exc:
        return f"unreadable: {exc}"


SIGNATURES = {
    "PassThruOpen": [C.c_void_p, P32],
    "PassThruClose": [U32],
    "PassThruReadVersion": [U32, C.POINTER(C.c_char), C.POINTER(C.c_char), C.POINTER(C.c_char)],
    "PassThruGetLastError": [C.POINTER(C.c_char)],
    "PassThruIoctl": [U32, U32, C.c_void_p, C.c_void_p],
    "PassThruConnect": [U32, U32, U32, U32, P32],
    "PassThruDisconnect": [U32],
    "PassThruStartMsgFilter": [U32, U32, C.POINTER(Message), C.POINTER(Message), C.POINTER(Message), P32],
    "PassThruWriteMsgs": [U32, C.POINTER(Message), P32, U32],
    "PassThruReadMsgs": [U32, C.POINTER(Message), P32, U32],
}


def message(can_id, payload=b""):
    if not 0 <= can_id <= 0x7FF or len(payload) > 4095:
        raise ValueError("需要 11 位 CAN ID 和最多 4095 字节载荷")
    data = can_id.to_bytes(4, "big") + payload
    result = Message(ProtocolID=ISO15765, TxFlags=FRAME_PAD,
                     DataSize=len(data), ExtraDataIndex=len(data))
    result.Data[:len(data)] = data
    return result


class DiagnosticError(OSError):
    def __init__(self, service, nrc):
        self.service, self.nrc = service, nrc
        super().__init__(f"控制器否定响应 NRC 0x{nrc:02x}；没有自动重发")


class DriverError(OSError):
    pass


class Device:
    def __init__(self, path):
        if sys.platform != "win32":
            raise OSError("J2534 驱动需要 Windows")
        path = Path(path)
        if not path.is_absolute() or path.suffix.lower() != ".dll":
            raise ValueError("请提供官方 J2534 v04.04 驱动 DLL 的绝对路径")
        path = path.resolve(strict=True)
        machine = platform.machine().upper()
        expected = "x86" if C.sizeof(C.c_void_p) == 4 else {
            "AMD64": "x64", "X86_64": "x64", "ARM64": "arm64", "AARCH64": "arm64"}.get(machine)
        actual = pe_architecture(path)
        if expected is None or actual != expected:
            raise ValueError(f"驱动架构 {actual} 与当前 Python 架构 {expected} 不匹配；请使用匹配位数的 Python")
        self.path = path
        self.dll = C.WinDLL(str(path), winmode=0x1100)
        for name, types in SIGNATURES.items():
            try:
                function = getattr(self.dll, name)
            except AttributeError as exc:
                raise ValueError(f"驱动缺少 J2534 v04.04 函数 {name}") from exc
            function.argtypes = types
            function.restype = C.c_int32
        self.device = None
        self.channel = None
        self.closed = False

    def check(self, name, *args):
        code = getattr(self.dll, name)(*args)
        if code:
            text = C.create_string_buffer(256)
            last_error = self.dll.PassThruGetLastError(text)
            detail = text.value.decode("mbcs", errors="replace") if last_error == 0 else ""
            # Some vendor wrappers replace their error text while cleaning up a failed Open.
            meaning = " (ERR_DEVICE_NOT_CONNECTED)" if code == 8 else ""
            raise DriverError(f"{name}: J2534 error 0x{code & 0xffffffff:08x}{meaning}; driver: {detail}")

    def __enter__(self):
        self.closed = False
        device = U32()
        self.check("PassThruOpen", None, C.byref(device))
        self.device = device.value
        return self

    def __exit__(self, exc_type, exc, tb):
        errors = []
        if self.channel is not None:
            try:
                self.check("PassThruDisconnect", self.channel)
            except OSError as error:
                errors.append(str(error))
        if self.device is not None:
            try:
                self.check("PassThruClose", self.device)
            except OSError as error:
                errors.append(str(error))
        self.channel = self.device = None
        self.closed = not errors
        if errors:
            raise OSError(f"{str(exc) + '; ' if exc else ''}清理失败: {'; '.join(errors)}") from exc
        return False

    def info(self):
        buffers = [C.create_string_buffer(80) for _ in range(3)]
        self.check("PassThruReadVersion", self.device, *buffers)
        firmware, library, api = [buffer.value.decode("ascii", errors="replace") for buffer in buffers]
        if not api.startswith("04.04"):
            raise ValueError(f"此实现只支持 J2534 v04.04，驱动报告 {api!r}")
        voltage = U32()
        code = self.dll.PassThruIoctl(self.device, 3, None, C.byref(voltage))
        return {"library": str(self.path), "library_sha256": hashlib.sha256(self.path.read_bytes()).hexdigest(),
                "firmware_version": firmware, "dll_version": library, "api_version": api,
                "battery_mv": voltage.value if code == 0 else None,
                "voltage_status": code}

    def connect_isotp(self, baud, pairs):
        if baud not in (250000, 500000):
            raise ValueError("CAN 通道只接受 250000 或 500000；需先确认车辆总线速率")
        if self.channel is not None:
            raise ValueError("当前设备已经存在协议通道")
        channel = U32()
        self.check("PassThruConnect", self.device, ISO15765, 0, baud, C.byref(channel))
        self.channel = channel.value
        for request_id, response_id in pairs:
            mask = message(0x7FF)
            mask.Data[:4] = b"\xff\xff\xff\xff"
            pattern = message(response_id)
            mask.TxFlags = pattern.TxFlags = 0
            flow = message(request_id)
            filter_id = U32()
            self.check("PassThruStartMsgFilter", self.channel, 3, C.byref(mask), C.byref(pattern),
                       C.byref(flow), C.byref(filter_id))

    def disconnect(self):
        if self.channel is not None:
            self.check("PassThruDisconnect", self.channel)
            self.channel = None

    def _write(self, request, entry):
        self.check("PassThruIoctl", self.channel, 8, None, None)
        count = U32(1)
        self.check("PassThruWriteMsgs", self.channel, C.byref(request), C.byref(count), 1000)
        if count.value != 1:
            raise DriverError("诊断请求未被完整发送；没有自动重发")
        entry["write_accepted"] = True

    def send_raw_can(self, frames, trace):
        """Switch to CAN for observed auxiliary frames; acceptance is not a vehicle ACK."""
        frames = list(frames)
        if self.device is None or not frames:
            raise ValueError("原始 CAN 发送需要已打开设备及非空帧列表")
        for can_id, payload in frames:
            message(can_id, payload)
            if not 1 <= len(payload) <= 8:
                raise ValueError("原始 CAN 帧需要 1 至 8 字节载荷")
        self.disconnect()
        channel = U32()
        self.check("PassThruConnect", self.device, 5, 0, 500000, C.byref(channel))
        self.channel = channel.value
        for can_id, payload in frames:
            request = message(can_id, payload)
            request.ProtocolID, request.TxFlags = 5, 0
            entry = {"tx_id": f"0x{can_id:03x}", "protocol": "CAN", "request_hex": payload.hex(),
                     "write_accepted": False, "vehicle_response_verified": False}
            trace.append(entry)
            self._write(request, entry)
        self.disconnect()

    def send_suppressed_tester_present(self, tx_id, trace):
        if self.channel is None:
            raise ValueError("请求需要已建立的通道")
        entry = {"tx_id": f"0x{tx_id:03x}", "request_hex": "3e80", "write_accepted": False,
                 "vehicle_response_verified": False, "positive_response_suppressed": True}
        trace.append(entry)
        self._write(message(tx_id, b"\x3e\x80"), entry)

    def exchange(self, tx_id, rx_id, payload, expected, trace):
        """One ISO15765 request; pending replies never cause a retransmission."""
        if self.channel is None or not payload or not expected:
            raise ValueError("请求需要已建立的通道、载荷和预期响应前缀")
        request = message(tx_id, payload)
        entry = {"tx_id": f"0x{tx_id:03x}", "rx_id": f"0x{rx_id:03x}",
                 "request_hex": payload.hex(), "write_accepted": False, "responses": []}
        trace.append(entry)
        self._write(request, entry)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            reply, count = Message(), U32(1)
            remaining = max(1, min(250, int((deadline - time.monotonic()) * 1000)))
            status = self.dll.PassThruReadMsgs(self.channel, C.byref(reply), C.byref(count), remaining)
            if status not in (0, 9, 0x10):
                text = C.create_string_buffer(256)
                self.dll.PassThruGetLastError(text)
                raise DriverError(f"PassThruReadMsgs: J2534 error 0x{status:08x} {text.value!r}")
            if count.value > 1:
                raise ValueError("驱动返回的消息数量超出缓冲区契约")
            if count.value == 0:
                continue
            entry["responses"].append({"rx_status": reply.RxStatus, "timestamp_us": reply.Timestamp,
                                       "data_hex": bytes(reply.Data[:min(reply.DataSize, 4128)]).hex()})
            if reply.DataSize > 4128 or reply.ExtraDataIndex > reply.DataSize:
                raise ValueError("驱动返回的消息长度无效")
            if reply.ProtocolID != ISO15765 or reply.RxStatus & (1 | 2 | 8):
                continue
            if reply.RxStatus & (0x10 | 0x80 | 0x100):
                raise ValueError("收到填充错误或不匹配的 CAN 寻址格式")
            if not 4 <= reply.ExtraDataIndex <= 4099:
                raise ValueError("驱动返回的 ISO15765 有效数据边界无效")
            data = bytes(reply.Data[:reply.ExtraDataIndex])
            if int.from_bytes(data[:4], "big") != rx_id:
                continue
            response = data[4:]
            if response[:1] == b"\x7f":
                if len(response) != 3 or response[1] != payload[0]:
                    raise ValueError("否定响应与当前请求不匹配")
                if response[2] == 0x78:
                    continue
                raise DiagnosticError(response[1], response[2])
            if not response.startswith(expected):
                raise ValueError(f"控制器响应前缀不匹配: {response.hex()}，预期 {expected.hex()}")
            entry["response_hex"] = response.hex()
            return response
        raise TimeoutError("5 秒内未收到最终诊断响应；没有自动重发")

    def vin(self, baud):
        # Standard emissions addresses only; these are not Porsche ECU/PDK programming IDs.
        self.connect_isotp(baud, [(response_id - 8, response_id) for response_id in range(0x7E8, 0x7F0)])
        self.check("PassThruIoctl", self.channel, 8, None, None)
        request = message(0x7DF, b"\x09\x02")
        count = U32(1)
        self.check("PassThruWriteMsgs", self.channel, C.byref(request), C.byref(count), 1000)
        if count.value != 1:
            raise OSError("VIN 请求未被完整发送；没有自动重发")
        responses = []
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            reply, count = Message(), U32(1)
            remaining = max(1, min(250, int((deadline - time.monotonic()) * 1000)))
            status = self.dll.PassThruReadMsgs(self.channel, C.byref(reply), C.byref(count), remaining)
            if status not in (0, 9, 0x10):
                # Preserve the driver's current last-error text; do not repeat the failing call.
                text = C.create_string_buffer(256)
                self.dll.PassThruGetLastError(text)
                raise OSError(f"PassThruReadMsgs: J2534 error 0x{status:08x} {text.value!r}")
            if count.value > 1:
                raise ValueError("驱动返回的消息数量超出缓冲区契约")
            if count.value == 0:
                continue
            if reply.DataSize > 4128 or reply.ExtraDataIndex > reply.DataSize:
                raise ValueError("驱动返回的消息长度无效")
            if reply.ProtocolID != ISO15765 or reply.RxStatus & (1 | 2 | 8):
                continue
            if reply.RxStatus & (0x10 | 0x80 | 0x100):
                raise ValueError("收到填充错误或不匹配的 CAN 寻址格式")
            end = reply.ExtraDataIndex
            data = bytes(reply.Data[:end])
            if len(data) != 24 or not 0x7E8 <= int.from_bytes(data[:4], "big") <= 0x7EF:
                continue
            if data[4:7] != b"\x49\x02\x01":
                continue
            vin = data[7:].decode("ascii", errors="replace")
            if not re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin):
                raise ValueError("VIN 应为 17 位合法 VIN 字符")
            responses.append({"can_id": f"0x{int.from_bytes(data[:4], 'big'):03x}", "vin": vin,
                              "timestamp_us": reply.Timestamp, "data_hex": data.hex()})
        if not responses:
            raise TimeoutError("5 秒内未收到标准 OBD VIN；不能据此推断车辆 ECU/TCU 不支持 OBD 编程")
        if len({reply["vin"] for reply in responses}) != 1:
            raise ValueError("多个响应中的 VIN 不一致")
        return {"vin": responses[0]["vin"], "responses": responses, "request_hex": "000007df0902",
                "baud": baud, "scope": "standard-obd-vin-only", "vehicle_flash_verified": False}


def probe(path, baud=None):
    with Device(path) as device:
        result = device.info()
        if baud is not None:
            result["obd"] = device.vin(baud)
    result["closed"] = True
    result["protocol_channel_created"] = baud is not None
    result["vehicle_flash_verified"] = False
    return result
