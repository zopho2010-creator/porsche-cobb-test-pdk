"""Native ctypes callback fixture: exercises the Windows ABI, not a physical adapter."""
import ctypes as C
from itertools import count
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import j2534 as J
import porsche981 as P


VIN = "00000000000000001"  # Synthetic identifier with an invalid manufacturer prefix.


class FakeDriver:
    def __init__(self):
        self.calls, self.filters, self.sent, self.queue = [], [], [], []
        self.fail = {}
        self.api_version = b"04.04"
        self.write_count = 1
        self.read_status = 0
        self.error_text = b"fixture failure"
        self.responses_by_request = None
        self.responses_by_frame = {}
        self.sent_parameters, self.connections = [], []
        factory = getattr(C, "WINFUNCTYPE", C.CFUNCTYPE)
        for name, args in J.SIGNATURES.items():
            method = getattr(self, name)

            def callback(*values, _method=method, _name=name):
                self.calls.append(_name)
                if _name in self.fail:
                    return self.fail[_name]
                return _method(*values)

            setattr(self, name, factory(C.c_int32, *args)(callback))

    def PassThruOpen(self, name, result):
        result[0] = 0  # Zero is a valid ID and must still be closed.
        return 0

    def PassThruClose(self, device):
        return 0

    def PassThruReadVersion(self, device, firmware, library, api):
        for target, value in ((firmware, b"fixture-fw"), (library, b"fixture-dll"), (api, self.api_version)):
            C.memmove(target, value + b"\0", len(value) + 1)
        return 0

    def PassThruGetLastError(self, text):
        C.memmove(text, self.error_text + b"\0", len(self.error_text) + 1)
        return 0

    def PassThruIoctl(self, channel, code, source, output):
        if code == 3:
            C.cast(output, J.P32)[0] = 13800
        return 0

    def PassThruConnect(self, device, protocol, flags, baud, result):
        self.connect_parameters = (device, protocol, flags, baud)
        self.connections.append(self.connect_parameters)
        result[0] = 0
        return 0

    def PassThruDisconnect(self, channel):
        return 0

    def PassThruStartMsgFilter(self, channel, kind, mask, pattern, flow, result):
        self.filters.append((kind, bytes(mask[0].Data[:mask[0].DataSize]),
                             bytes(pattern[0].Data[:pattern[0].DataSize]),
                             bytes(flow[0].Data[:flow[0].DataSize])))
        result[0] = len(self.filters)
        return 0

    def PassThruWriteMsgs(self, channel, message, number, timeout):
        self.sent.append(bytes(message[0].Data[:message[0].DataSize]))
        self.sent_parameters.append((message[0].ProtocolID, message[0].TxFlags))
        if self.responses_by_request is not None:
            self.queue.extend(self.responses_by_frame.get(self.sent[-1], self.responses_by_request.get(self.sent[-1][4:], [])))
        number[0] = self.write_count
        return 0

    def PassThruReadMsgs(self, channel, message, number, timeout):
        if not self.queue:
            number[0] = 0
            return 0x10
        message[0] = self.queue.pop(0)
        number[0] = 1
        return self.read_status


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="J2534 space ")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "synthetic-driver.dll"
        machine = 0x8664 if C.sizeof(C.c_void_p) == 8 else 0x14C
        self.path.write_bytes(b"MZ" + bytes(58) + struct.pack("<I", 64) + b"PE\0\0" + struct.pack("<H", machine))
        self.fake = FakeDriver()
        self.loader = patch.object(C, "WinDLL", return_value=self.fake)
        self.load = self.loader.start()
        self.addCleanup(self.loader.stop)
        clock = count(0, 0.1)
        self.clock = patch.object(J.time, "monotonic", side_effect=lambda: next(clock))
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def test_probe_opens_closes_zero_device_id_without_bus_channel(self):
        result = J.probe(self.path)
        self.assertTrue(result["closed"])
        self.assertEqual(result["battery_mv"], 13800)
        self.assertFalse(result["protocol_channel_created"])
        self.assertEqual(self.fake.calls, ["PassThruOpen", "PassThruReadVersion", "PassThruIoctl", "PassThruClose"])

    def test_vin_native_ffi_flow_control_echo_filtering_and_cleanup(self):
        echo = J.message(0x7DF, b"\x09\x02")
        echo.RxStatus = 1
        first = J.message(0x7E8)
        first.RxStatus = 2
        reply = J.message(0x7E8, b"\x49\x02\x01" + VIN.encode())
        self.fake.queue = [echo, first, reply]
        result = J.probe(self.path, 500000)
        self.assertEqual(result["obd"]["vin"], VIN)
        self.assertFalse(result["vehicle_flash_verified"])
        self.assertEqual(self.fake.connect_parameters, (0, 6, 0, 500000))
        self.assertEqual(len(self.fake.filters), 8)
        self.assertEqual(self.fake.filters[0], (3, b"\xff" * 4, b"\0\0\x07\xe8", b"\0\0\x07\xe0"))
        self.assertEqual(self.fake.sent, [b"\0\0\x07\xdf\x09\x02"])
        self.assertEqual(self.fake.calls[-2:], ["PassThruDisconnect", "PassThruClose"])

    def test_filter_failure_disconnects_and_never_transmits(self):
        self.fake.fail["PassThruStartMsgFilter"] = 0x17
        with self.assertRaisesRegex(OSError, "00000017"):
            J.probe(self.path, 500000)
        self.assertEqual(self.fake.sent, [])
        self.assertEqual(self.fake.calls[-2:], ["PassThruDisconnect", "PassThruClose"])

    def test_version_failure_closes_device(self):
        self.fake.api_version = b"05.00"
        with self.assertRaisesRegex(ValueError, "04.04"):
            J.probe(self.path)
        self.assertEqual(self.fake.calls[-1], "PassThruClose")
        self.assertNotIn("PassThruConnect", self.fake.calls)

    def test_empty_queue_times_out_and_closes_both_handles(self):
        with self.assertRaises(TimeoutError):
            J.probe(self.path, 500000)
        self.assertEqual(self.fake.calls[-2:], ["PassThruDisconnect", "PassThruClose"])

    def test_malformed_driver_message_is_rejected(self):
        bad = J.message(0x7E8)
        bad.DataSize = 5000
        self.fake.queue = [bad]
        with self.assertRaisesRegex(ValueError, "长度无效"):
            J.probe(self.path, 500000)
        self.assertEqual(self.fake.calls[-2:], ["PassThruDisconnect", "PassThruClose"])

    def test_inconsistent_vins_are_not_accepted(self):
        self.fake.queue = [J.message(0x7E8, b"\x49\x02\x01" + VIN.encode()),
                           J.message(0x7E9, b"\x49\x02\x0100000000000000002")]
        with self.assertRaisesRegex(ValueError, "VIN 不一致"):
            J.probe(self.path, 500000)

    def test_close_failure_preserves_original_error(self):
        self.fake.fail["PassThruStartMsgFilter"] = 0x17
        self.fake.fail["PassThruClose"] = 0x08
        with self.assertRaisesRegex(OSError, "00000017.*清理失败.*00000008"):
            J.probe(self.path, 500000)

    def test_mismatched_dll_is_rejected_before_load(self):
        data = bytearray(self.path.read_bytes())
        machine = 0x14C if C.sizeof(C.c_void_p) == 8 else 0x8664
        struct.pack_into("<H", data, 68, machine)
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "不匹配"):
            J.Device(self.path)
        self.load.assert_not_called()

    def test_open_failure_does_not_close_an_unopened_device(self):
        self.fake.fail["PassThruOpen"] = 8
        with self.assertRaisesRegex(OSError, "00000008"):
            J.probe(self.path)
        self.assertNotIn("PassThruClose", self.fake.calls)

    def test_disconnected_code_is_preserved_when_vendor_text_is_misleading(self):
        self.fake.fail["PassThruOpen"] = 8
        self.fake.error_text = b"FAILED TO LOAD SMJ2534.DLL"
        with self.assertRaisesRegex(OSError, "0x00000008.*ERR_DEVICE_NOT_CONNECTED.*driver: FAILED TO LOAD SMJ2534"):
            J.probe(self.path)
        self.assertNotIn("PassThruConnect", self.fake.calls)

    def test_connect_failure_still_closes_device(self):
        self.fake.fail["PassThruConnect"] = 8
        with self.assertRaises(OSError):
            J.probe(self.path, 500000)
        self.assertEqual(self.fake.calls[-1], "PassThruClose")
        self.assertNotIn("PassThruDisconnect", self.fake.calls)

    def test_unsent_request_is_not_retried(self):
        self.fake.write_count = 0
        with self.assertRaisesRegex(OSError, "未被完整发送"):
            J.probe(self.path, 500000)
        self.assertEqual(len(self.fake.sent), 1)
        self.assertNotIn("PassThruReadMsgs", self.fake.calls)

    def test_partial_read_timeout_can_still_return_a_valid_message(self):
        self.fake.read_status = 9
        self.fake.queue = [J.message(0x7E8, b"\x49\x02\x01" + VIN.encode())]
        self.assertEqual(J.probe(self.path, 500000)["obd"]["vin"], VIN)

    def test_porsche_ecu_identity_uses_recovered_physical_address_and_service(self):
        self.fake.responses_by_request = {
            b"\x10\x89": [J.message(0x7E8, b"\x50\x89")],
            b"\x1a\x95": [J.message(0x7E8, b"\x5a\x95W06C30C1348EM16")],
            b"\x10\x81": [J.message(0x7E8, b"\x50\x81")],
        }
        result = P.identify(self.path, "ecu")
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["closed"])
        self.assertEqual(result["software_revision"], "W06C30C1348EM16")
        self.assertEqual(self.fake.sent, [b"\0\0\x07\xe0" + x for x in (b"\x10\x89", b"\x1a\x95", b"\x10\x81")])
        self.assertEqual(self.fake.filters, [(3, b"\xff" * 4, b"\0\0\x07\xe8", b"\0\0\x07\xe0")])
        self.assertEqual(self.fake.connect_parameters, (0, 6, 0, 500000))
        self.assertFalse(result["vehicle_flash_verified"])

    def test_porsche_pdk_identity_uses_71e_788_and_combines_two_reads(self):
        responses = {b"\x10\x81": b"\x50\x81", b"\x10\x89": b"\x50\x89",
                     b"\x22\xf0\x03": b"\x62\xf0\x03Q061  ", b"\x1a\x8a": b"\x5a\x8aCQID61DYC"}
        self.fake.responses_by_request = {k: [J.message(0x788, v)] for k, v in responses.items()}
        result = P.identify(self.path, "pdk")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["software_revision"], "Q061_CQID61DYC")
        self.assertEqual([x[:4] for x in self.fake.sent], [b"\0\0\x07\x1e"] * 4)
        self.assertEqual(self.fake.filters[0][2:], (b"\0\0\x07\x88", b"\0\0\x07\x1e"))
        self.assertEqual([x[4:] for x in self.fake.sent], list(responses))

    def test_identity_pending_and_echo_are_logged_without_request_resend(self):
        echo = J.message(0x7E0, b"\x1a\x95")
        echo.RxStatus = 1
        self.fake.responses_by_request = {
            b"\x10\x89": [J.message(0x7E8, b"\x50\x89")],
            b"\x1a\x95": [echo, J.message(0x7E8, b"\x7f\x1a\x78"),
                                    J.message(0x7E8, b"\x5a\x95W06C30C1348EM16")],
            b"\x10\x81": [J.message(0x7E8, b"\x50\x81")],
        }
        result = P.identify(self.path, "ecu")
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(self.fake.sent), 3)
        self.assertEqual(len(result["transactions"][1]["responses"]), 3)

    def test_wrong_identity_subfunction_fails_and_preserves_trace_and_cleanup(self):
        self.fake.responses_by_request = {
            b"\x10\x89": [J.message(0x7E8, b"\x50\x89")],
            b"\x1a\x95": [J.message(0x7E8, b"\x5a\x94WRONG")],
        }
        result = P.identify(self.path, "ecu")
        self.assertFalse(result["ok"])
        self.assertTrue(result["closed"])
        self.assertNotIn("software_revision", result)
        self.assertIn("前缀不匹配", result["error"])
        self.assertEqual(len(result["transactions"]), 2)
        self.assertEqual(self.fake.calls[-2:], ["PassThruDisconnect", "PassThruClose"])

    def test_identity_negative_response_aborts_without_busy_retry(self):
        self.fake.responses_by_request = {b"\x10\x89": [J.message(0x7E8, b"\x7f\x10\x21")]}
        result = P.identify(self.path, "ecu")
        self.assertFalse(result["ok"])
        self.assertIn("NRC 0x21", result["error"])
        self.assertEqual(len(self.fake.sent), 1)
        self.assertTrue(result["transactions"][0]["write_accepted"])

    def test_identity_pending_has_absolute_timeout_and_preserves_failure(self):
        self.fake.responses_by_request = {b"\x10\x89": [J.message(0x7E8, b"\x7f\x10\x78")]}
        result = P.identify(self.path, "ecu")
        self.assertFalse(result["ok"])
        self.assertIn("5 秒", result["error"])
        self.assertEqual(len(self.fake.sent), 1)
        self.assertTrue(result["closed"])

    def test_identity_filter_failure_never_sends(self):
        self.fake.fail["PassThruStartMsgFilter"] = 0x17
        result = P.identify(self.path, "pdk")
        self.assertFalse(result["ok"])
        self.assertEqual(self.fake.sent, [])
        self.assertEqual(result["transactions"], [])
        self.assertTrue(result["closed"])

    def test_identity_rejects_empty_or_binary_identity_text(self):
        for value in (b"", b"\x00\x01", b"   "):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    P.identity_text(value)

    def test_synthetic_transfer_chunks_cross_real_ctypes_boundary(self):
        for target, length in (("ecu", 248), ("pdk", 512)):
            profile = P.PROFILES[target]
            request = b"\x36" + bytes(i % 256 for i in range(length))
            self.fake.responses_by_request = {request: [J.message(profile["rx"], b"\x76")]}
            trace = []
            with J.Device(self.path) as device:
                device.connect_isotp(500000, [(profile["tx"], profile["rx"])])
                self.assertEqual(device.exchange(profile["tx"], profile["rx"], request, b"\x76", trace), b"\x76")
            self.assertEqual(self.fake.sent[-1], profile["tx"].to_bytes(4, "big") + request)
            self.assertEqual(trace[0]["response_hex"], "76")

    def test_lost_transfer_ack_never_resends_an_accepted_write(self):
        trace = []
        with self.assertRaises(TimeoutError):
            with J.Device(self.path) as device:
                device.connect_isotp(500000, [(0x7e0, 0x7e8)])
                device.exchange(0x7e0, 0x7e8, b"\x36synthetic", b"\x76", trace)
        self.assertEqual(len(self.fake.sent), 1)
        self.assertTrue(trace[0]["write_accepted"])
        self.assertNotIn("response_hex", trace[0])
        self.assertTrue(device.closed)

    def test_transfer_pending_then_ack_does_not_resend(self):
        request = b"\x36synthetic"
        self.fake.responses_by_request = {request: [J.message(0x788, b"\x7f\x36\x78"),
                                                   J.message(0x788, b"\x76")]}
        trace = []
        with J.Device(self.path) as device:
            device.connect_isotp(500000, [(0x71e, 0x788)])
            device.exchange(0x71e, 0x788, request, b"\x76", trace)
        self.assertEqual(len(self.fake.sent), 1)
        self.assertEqual(len(trace[0]["responses"]), 2)

    def test_security_rejection_stops_without_following_programming_requests(self):
        request = b"\x27\x01"
        self.fake.responses_by_request = {request: [J.message(0x7e8, b"\x7f\x27\x33")]}
        with self.assertRaisesRegex(OSError, "NRC 0x33"):
            with J.Device(self.path) as device:
                device.connect_isotp(500000, [(0x7e0, 0x7e8)])
                device.exchange(0x7e0, 0x7e8, request, b"\x67\x01", [])
        self.assertEqual([frame[4:] for frame in self.fake.sent], [request])

    def test_mismatched_transfer_response_cannot_report_success(self):
        request = b"\x36synthetic"
        self.fake.responses_by_request = {request: [J.message(0x7e8, b"\x77")]}
        with self.assertRaisesRegex(ValueError, "前缀不匹配"):
            with J.Device(self.path) as device:
                device.connect_isotp(500000, [(0x7e0, 0x7e8)])
                device.exchange(0x7e0, 0x7e8, request, b"\x76", [])
        self.assertEqual(len(self.fake.sent), 1)


if __name__ == "__main__":
    unittest.main()
