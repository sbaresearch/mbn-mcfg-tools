import hashlib
import logging
import os
import json

from pathlib import Path
from typing import Optional

from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
from mbntools.mcfg import MCFG, MCFG_Item
from mbntools.utils import write_all, get_bytes, pack
from mbntools import utils
from mbntools.mbn_json import MbnJsonEncoder, decode_hook

logger = logging.getLogger(__name__)

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
        nv_items = []
        path = Path(path)
        files_path = utils.join(Path(path), Path("files"))
        used_paths = set()
        for item in self["mcfg"]["items"]:
            if item["type"] == MCFG_Item.NV_TYPE:
                it = item._header.copy()
                it["ascii"] = it["data"].decode("ascii", errors="replace").replace('\ufffd', '.')
                it["data"] = it["data"].hex(' ', -1)
                nv_items.append(it)
                continue

            p = utils.join(files_path, Path(item["filename"].decode().strip('\x00')))
            p.resolve()

            if files_path not in p.parents:
                logger.warn(f"File would escape extract dir (skipping): {p}")
                continue

            p.parent.mkdir(parents=True, exist_ok=True)

            free_p = free_name(p, used_paths)

            if free_p != p:
                item["filename_alias"] = str(free_p)

            with open(free_p, "xb") as f:
                write_all(f, item["data"])

        with open(path / "nv_items", "x") as f:
            json.dump(nv_items, f, indent=2)
        with open(path / "meta", "x") as f:
            write_all(f, MbnJsonEncoder(extract_meta=True, indent=2).encode(self["mcfg"]))
        with open(path / "original_file.mbn", "xb") as f:
            self._stream.seek(0)
            buf = self._stream.read() # TODO: avoid reading everything at once
            write_all(f, buf)
        with open(path / "mcfg_end", "xb") as f:
            write_all(f, self["mcfg_end"])

        for item in self["mcfg"]["items"]:
            try:
                del item["filename_alias"]
            except:
                pass
            else:
                print("deleted *smh*")

    # TODO: prevent overwriting
    @staticmethod
    def unextract(exdir, path, use_defaults=True) -> "Mbn":
        def create_default_item(fname: Optional[bytes] = None):
            item = MCFG_Item.__new__(MCFG_Item)
            item._header = {
                    "type": MCFG_Item.NV_TYPE, # TODO: find suitable default
                    "attributes": 0,
                    "reserved": 0,
                    }
            if fname is not None:
                item["filename"] = fname
                item["type"] = MCFG_Item.FILE_TYPE

            return item

        exdir = Path(exdir)

        if not all(map(lambda n: (exdir / n).exists(), ["nv_items", "meta", "original_file.mbn", "files"])):
            raise Exception("Extracted file is incomplete!")

        with open(exdir / "meta", "r") as f:
            mcfg = json.load(f, object_hook=decode_hook)

        with open(exdir / "nv_items", "r") as f:
            nv_items = json.load(f)

        with open(exdir / "mcfg_end", "rb") as f:
            mcfg_end = f.read()

        mcfg_nv_items = []
        for nv_item in nv_items:
            item = MCFG_Item.__new__(MCFG_Item)
            item._header = nv_item
            del item._header["ascii"]
            item["data"] = bytes.fromhex(item["data"])
            mcfg_nv_items.append(item)

        for dirp, _, fps in os.walk(exdir / "files"): # TODO use onerror
            for fp in fps:
                fp = Path(dirp) / fp

                name = fp.relative_to(exdir / "files")
                items = mcfg._find_filepath(str("/" / name).encode())

                if len(items) == 0:
                    if use_defaults:
                        item = create_default_item(str("/" / fp.relative_to(exdir / "files")).encode() + b'\x00')
                        mcfg["items"].append(item)
                    else:
                        raise NotImplementedError
                elif len(items) == 1:
                    item = items[0]
                else:
                    raise AssertionError

                with open(fp, "rb") as f:
                    item["data"] = f.read()

        # TODO: remove NV Items from 'meta' during extraction
        mcfg["items"] = list(filter(lambda x: "data" in x, mcfg["items"]))
        mcfg["items"] = mcfg_nv_items + mcfg["items"]

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

def free_name(name: Path, used: set[Path]) -> Path:
    n = name
    i = 1

    while n in used:
        n = name.with_name(name.name + f"_({i})")
        i += 1

    used.add(n)
    return n
