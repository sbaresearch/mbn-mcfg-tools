import hashlib
import logging

from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
from mbntools.mcfg import MCFG
from mbntools.utils import write_all, get_bytes, pack

logger = logging.getLogger(__name__)

class Mbn:
    def __init__(self, stream):
        self.stream = stream
        self.values = {}

    def parse(self):
        self["elf"] = ELFFile(self.stream)
        self.stream.seek(self["elf"].get_segment(2)["p_offset"])
        self["mcfg"] = MCFG(self.stream)
        self["mcfg"].parse()
        self._parse_mcfg_end()

    def _parse_mcfg_end(self):
        offset = self.stream.tell()

        *_, last_seg = self["elf"].iter_segments()
        mcfg_end = last_seg["p_offset"] + last_seg["p_filesz"]

        logger.debug(f"Posiiton before calc. diff. {self.stream.tell()}")
        diff = mcfg_end - offset

        self["mcfg_end"] = b""
        if diff == 0:
            return
        elif diff < 0:
            logger.warn("MCFG parser read past MCFG segment end.")
        else:
            self.stream.seek(offset)
            self["mcfg_end"] = get_bytes(self.stream, diff)

    def rewrite_hashes(self):
        n, hseg = self._get_hash_segment()

        for i, s in enumerate(self["elf"].iter_segments()):
            if i == n:
                self.stream.seek(hseg["p_offset"] + 40 + i * 32)
                write_all(self.stream, b'\x00' * 32)
                continue

            h = hashlib.sha256(s.data())
            self.stream.seek(hseg["p_offset"] + 40 + i * 32)
            write_all(self.stream, h.digest())

    def check_hashes(self) -> bool:
        n, hseg = self._get_hash_segment()
        num_segs = self["elf"].num_segments()
        hashes = []
        data = hseg.data()[40:]
        for _ in range(num_segs):
            hashes.append(data[:32])
            data = data[32:]

        if hashes[n] != b'\x00' * 32:
            return False

        for i, s in enumerate(self["elf"].iter_segments()):
            if i == n:
                continue

            h = hashlib.sha256(s.data())

            if hashes[i] != h.digest():
                return False

        return True

    def _get_hash_segment(self) -> tuple[int, Segment]:
        mseg = list(filter(lambda x: x[1]["p_flags"] & 0x200000 != 0, enumerate(self["elf"].iter_segments())))

        if len(mseg) == 0:
            raise Exception("Missing hash segment")
        if len(mseg) > 1:
            raise Exception("Found multiple hash segments")

        return mseg[0]

    def write(self):
        if self["elf"].num_segments() != 3:
            raise NotImplementedError

        self.stream.seek(self["elf"].get_segment(2)["p_offset"])
        start = self.stream.tell()
        self["mcfg"].write()
        write_all(self.stream, self["mcfg_end"])
        stop = self.stream.tell()
        size = stop - start

        filesz_off = self["elf"]["e_phoff"] + 2 * self["elf"]["e_phentsize"]
        if self["elf"].elfclass == 32:
            sizefmt = "I"
            filesz_off += 16
        elif self["elf"].elfclass == 64:
            sizefmt = "Q"
            filesz_off += 32
        else:
            raise Exception("Unknown elf class")

        self.stream.seek(filesz_off)
        endianness = "<" if self["elf"].little_endian else ">"
        pack(endianness + sizefmt, self.stream, size)

    def __getitem__(self, k):
        return self.values[k]

    def __setitem__(self, k, v):
        self.values[k] = v
