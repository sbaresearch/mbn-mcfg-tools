import struct

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

def write_all(stream, b: bytes):
    while len(b) > 0:
        x = stream.write(b)
        b = b[x:]

def pack(fmt: str, stream, *args):
    b = struct.pack(fmt, *args)
    write_all(stream, b)
