import struct


def be16(value: int) -> bytes:
    return struct.pack(">H", value)


def be32(value: int) -> bytes:
    return struct.pack(">I", value)


def crc16(data: bytes) -> int:
    """CRC-16/ARC (reflected polynomial 0xA001). SAP's frame checksum."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc
