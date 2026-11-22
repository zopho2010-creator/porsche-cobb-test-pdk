"""Offline SDI segment codec recovered from POR-007; no checksum repair or vehicle IO."""
import struct


MAX_SEGMENT_SIZE = 0x400000


def _parameters(marker, window_bits, length_bits):
    if not (0 <= marker <= 255 and 1 <= window_bits <= 15 and
            1 <= length_bits <= 15 and window_bits + length_bits <= 16):
        raise ValueError("SDI 压缩参数无效")


def compress_segment(data, marker, window_bits, length_bits, fast=True):
    """CompressSegment, including its trailing literal and observed fast=true flash path."""
    _parameters(marker, window_bits, length_bits)
    if len(data) > MAX_SEGMENT_SIZE:
        raise ValueError("SDI 原始段超出已研究尺寸")
    packed, position = bytearray(), 0
    while position < len(data):
        if data[position] == marker:
            packed.extend((marker, 0, 0))
        else:
            window = min((1 << window_bits) - 1, position, len(data) - position - 1)
            length = min((1 << length_bits) - 1, window)
            if window > 3:
                # FindMatch searches oldest to newest and excludes overlapping candidates.
                for length in range(length, length - 1 if fast else 3, -1):
                    found = data.find(data[position:position + length], position - window, position)
                    if found >= 0:
                        token = ((position - found) << length_bits) | length
                        packed.extend((marker, token >> 8, token & 255))
                        position += length
                        break
        packed.append(data[position])
        position += 1
    return bytes((marker, window_bits, length_bits)) + struct.pack(">II", len(data), len(packed) + 11) + packed


def decompress_segment(data):
    if len(data) < 11:
        raise ValueError("SDI 段头截断")
    marker, window_bits, length_bits = data[:3]
    _parameters(marker, window_bits, length_bits)
    original_size, packed_size = struct.unpack_from(">II", data, 3)
    if original_size > MAX_SEGMENT_SIZE or packed_size != len(data):
        raise ValueError("SDI 段头尺寸无效")
    output, position = bytearray(), 11
    while position < len(data):
        literal = data[position]
        if literal == marker:
            if position + 4 > len(data):
                raise ValueError("SDI 压缩令牌或尾随字节截断")
            token = int.from_bytes(data[position + 1:position + 3], "big")
            distance, length = token >> length_bits, token & ((1 << length_bits) - 1)
            if (length and (distance == 0 or distance > len(output))) or distance >= 1 << window_bits:
                raise ValueError("SDI 回溯引用无效")
            if not length and token:
                raise ValueError("SDI 零长度转义令牌无效")
            if len(output) + length + 1 > original_size:
                raise ValueError("SDI 解压内容超过声明尺寸")
            for _ in range(length):
                output.append(output[-distance])
            position += 3
            literal = data[position]
        output.append(literal)
        if len(output) > original_size:
            raise ValueError("SDI 解压内容超过声明尺寸")
        position += 1
    if len(output) != original_size:
        raise ValueError("SDI 解压尺寸与声明不符")
    return bytes(output)
