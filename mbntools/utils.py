import struct

from pathlib import Path

def unpack(fmt: str, stream) -> tuple:
    l = struct.calcsize(fmt)
    return struct.unpack(fmt, get_bytes(stream, l))

def get_bytes(stream, n) -> bytes:
    if n <= 0:
        return b""

    b = b""
    while n > 0:
        b += stream.read(n)

        if len(b) == 0:
            raise EOFError

        n -= len(b)

    return b

def write_all(stream, b):
    #print(f"write_all: {hex(stream.tell())} b: {b[:4]}")
    while len(b) > 0:
        x = stream.write(b)
        b = b[x:]

def pack(fmt: str, stream, *args):
    b = struct.pack(fmt, *args)
    write_all(stream, b)

def join(x: Path, y: Path) -> Path:
    y = y.relative_to('/') if y.is_absolute() else y
    return x / y
