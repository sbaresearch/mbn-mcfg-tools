import hashlib
import logging
import json

from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
from mbntools.mcfg import MCFG, MCFG_Item
from mbntools.utils import write_all, get_bytes, pack
from mbntools import utils
from mbntools.mbn_json import MbnJsonEncoder, decode_hook

logger = logging.getLogger(__name__)

# TODO: context manager
class Mbn:
    def __init__(self, stream):
        self._stream = stream
        self._values = {}
        self.parse()

    def parse(self):
        self["elf"] = ELFFile(self._stream)
        self._stream.seek(self.get_mcfg_seg()["p_offset"])
        self["mcfg"] = MCFG(self._stream)
        self._parse_mcfg_end()

    def extract(self, path):
        encoder = MbnJsonEncoder(extract_meta=True, indent=2)

        nv_items = []
        path = Path(path)
        files_path = utils.join(Path(path), Path("files"))
        used_paths = set()
        for item in self["mcfg"]["items"]:
            if item["type"] == MCFG_Item.NV_TYPE:
                nv_items.append(item)
                continue

            filename = Path(item["filename"].strip(b'\x00').decode())
            free_name = _free_name(filename, used_paths)

            if free_name != filename:
                item["filename_alias"] = bytes(free_name)
                filename = free_name

            p = utils.join(files_path, filename)
            p.resolve()

            if files_path not in p.parents:
                logger.warn(f"File would escape extract dir (skipping): {p}")
                continue

            p.parent.mkdir(parents=True, exist_ok=True)

            with open(p, "xb") as f:
                write_all(f, item["data"])

            nv_items.append(item)

        with open(path / "nv_items", "x") as f:
            json.dump(nv_items, f, indent=2, default=encoder.default)
        with open(path / "meta", "x") as f:
            write_all(f, encoder.encode(self["mcfg"]))
        with open(path / "original_file.mbn", "xb") as f:
            self._stream.seek(0)
            buf = self._stream.read() # TODO: avoid reading everything at once
            write_all(f, buf)
        with open(path / "mcfg_end", "xb") as f:
            write_all(f, self["mcfg_end"])

        for item in self["mcfg"]["items"]:
            try:
                del item._header["filename_alias"]
            except:
                pass

    # TODO: prevent overwriting
    @staticmethod
    def unextract(exdir, path) -> "Mbn":
        exdir = Path(exdir)

        if not all(map(lambda n: (exdir / n).exists(), ["nv_items", "meta", "original_file.mbn", "files"])):
            raise Exception("Extracted file is incomplete!")

        with open(exdir / "meta", "r") as f:
            mcfg = json.load(f, object_hook=decode_hook)

        with open(exdir / "nv_items", "r") as f:
            nv_items = json.load(f, object_hook=decode_hook)

        with open(exdir / "mcfg_end", "rb") as f:
            mcfg_end = f.read()

        mcfg["items"] = []
        for item in nv_items:
            if item["type"] == MCFG_Item.NV_TYPE:
                mcfg["items"].append(item)
                continue

            fp = _extracted_filename(item)
            with open(utils.join(exdir / "files", fp), "rb") as f: # TODO error handling
                item["data"] = f.read()

            mcfg["items"].append(item)

        for item in mcfg["items"]:
            try:
                del item["filename_alias"]
            except:
                pass

        stream = open(path, "w+b") # TODO
        with open(exdir / "original_file.mbn", "rb") as orig:
            write_all(stream, orig.read())
        stream.seek(0)
        mbn = Mbn.__new__(Mbn)
        mbn._stream = stream # TODO: set stream for subcomponents
        mbn._values = {
                "elf": ELFFile(stream),
                "mcfg": mcfg,
                "mcfg_end": mcfg_end,
                }
        mbn["mcfg"]._stream = stream
        for i in mbn["mcfg"]["items"]:
            i._stream = stream
        mbn["mcfg"]["trailer"]._stream = stream
        return mbn

    def get_mcfg_seg(self) -> Segment:
        return self["elf"].get_segment(2)

    def _parse_mcfg_end(self):
        offset = self._stream.tell()

        *_, last_seg = self["elf"].iter_segments()
        mcfg_end = last_seg["p_offset"] + last_seg["p_filesz"]

        logger.debug(f"Posiiton before calc. diff. {self._stream.tell()}")
        diff = mcfg_end - offset

        self["mcfg_end"] = b""
        if diff == 0:
            return
        elif diff < 0:
            logger.warn("MCFG parser read past MCFG segment end.")
        else:
            self._stream.seek(offset)
            self["mcfg_end"] = get_bytes(self._stream, diff)

    def rewrite_hashes(self):
        n, hseg = self._get_hash_segment()

        for i, s in enumerate(self["elf"].iter_segments()):
            if i == n:
                self._stream.seek(hseg["p_offset"] + 40 + i * 32)
                write_all(self._stream, b'\x00' * 32)
                continue

            h = hashlib.sha256(s.data())
            self._stream.seek(hseg["p_offset"] + 40 + i * 32)
            write_all(self._stream, h.digest())

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

        self._stream.seek(self["elf"].get_segment(2)["p_offset"])
        start = self._stream.tell()
        self["mcfg"].write()
        write_all(self._stream, self["mcfg_end"])
        self._stream.truncate()
        stop = self._stream.tell()
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

        self._stream.seek(filesz_off)
        endianness = "<" if self["elf"].little_endian else ">"
        pack(endianness + 2 * sizefmt, self._stream, size, size)

    def __getitem__(self, k):
        return self._values[k]

    def __setitem__(self, k, v):
        self._values[k] = v

    def __contains__(self, k):
        return k in self._values

def _free_name(name: Path, used: set[Path]) -> Path:
    n = name
    i = 1

    while n in used:
        n = name.with_name(name.name + f"_({i})")
        i += 1

    used.add(n)
    return n

def _extracted_filename(item: MCFG_Item) -> Path:
    n = item["filename_alias"] if "filename_alias" in item else item["filename"]
    return Path(n.strip(b'\x00').decode())
