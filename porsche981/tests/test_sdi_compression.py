from pathlib import Path
import random
import struct
import unittest

from sdi_compression import compress_segment, decompress_segment, MAX_SEGMENT_SIZE


class SegmentCodec(unittest.TestCase):
    def test_literals_escape_and_mandatory_trailing_literal(self):
        for data, expected in ((b"ABC", b"ABC"), (b"A\xe1B", b"A\xe1\0\0\xe1B"),
                               (b"abcdabcdZ", b"abcd\xe1\x02\x04Z"), (b"", b"")):
            for fast in (True, False):
                encoded = compress_segment(data, 0xe1, 9, 7, fast)
                self.assertEqual(encoded[11:], expected)
                self.assertEqual(decompress_segment(encoded), data)

    def test_roundtrips_source_parameter_sets_and_binary_boundaries(self):
        rng = random.Random(981)
        for marker, window, length in ((0xe1, 9, 7), (0xb9, 5, 11)):
            for size in (1, 3, 4, 31, 32, 127, 128, 511, 512, 1024):
                for data in (b"\0" * size, bytes([marker]) * size,
                             bytes(rng.randrange(256) for _ in range(size))):
                    for fast in (True, False):
                        self.assertEqual(decompress_segment(compress_segment(data, marker, window, length, fast)), data)

    def test_rejects_truncation_bad_references_and_expansion(self):
        def frame(payload, size):
            return b"\xe1\x09\x07" + struct.pack(">II", size, len(payload) + 11) + payload
        malformed = [b"", bytes(11), frame(b"\xe1", 1), frame(b"\xe1\0\0", 1),
                     frame(b"\xe1\0\x81Z", 2), frame(b"A\xe1\0\x01Z", 3),
                     frame(b"A\xe1\0\x80Z", 2), frame(b"A", 2), frame(b"A", 0),
                     frame(b"", MAX_SEGMENT_SIZE + 1)]
        for data in malformed:
            with self.subTest(data=data.hex()), self.assertRaises(ValueError):
                decompress_segment(data)
        for marker, window, length in ((256, 9, 7), (1, 0, 7), (1, 9, 8)):
            with self.assertRaises(ValueError):
                compress_segment(b"", marker, window, length)
        with self.assertRaises(ValueError):
            decompress_segment(compress_segment(b"ABC", 0xe1, 9, 7) + b"X")

    def test_real_precompressed_segments_decode_and_reencode(self):
        path = Path(__file__).resolve().parents[1] / "samples/ap-stock-containers/roms/PORS_W06C30C1.rom"
        if not path.exists():
            self.skipTest("Optional original ROM fixture is not present")
        data = path.read_bytes()
        for offset in (0x18000, 0x180000, 0x240000):
            length = struct.unpack_from(">I", data, offset + 7)[0]
            packed = data[offset:offset + length]
            decoded = decompress_segment(packed)
            self.assertEqual(len(decoded), int.from_bytes(packed[3:7], "big"))
            self.assertEqual(decompress_segment(compress_segment(decoded, *packed[:3])), decoded)


if __name__ == "__main__":
    unittest.main()
