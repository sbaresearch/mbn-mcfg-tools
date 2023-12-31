import hashlib
import logging
import json
import struct
import os

from io import BytesIO
from pathlib import Path
from typing import BinaryIO

from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
from mbn_mcfg_tools.mcfg import MCFG, MCFG_Item
from mbn_mcfg_tools.utils import write_all, get_bytes, pack
from mbn_mcfg_tools import utils
from mbn_mcfg_tools.mbn_json import MbnJsonEncoder, decode_hook, NvContentEncoder
from mbn_mcfg_tools import items_generated
from mbn_mcfg_tools.hash_header import parse_hash_header

logger = logging.getLogger(__name__)


class Mbn:
    def __init__(self, stream: BinaryIO, parse_trailer_content=True):
        self._stream = stream
        self._values = {}
        self._parse_trailer_content = parse_trailer_content
        self.parse()

    def parse(self):
        self["elf"] = ELFFile(self._stream)
        self._stream.seek(self.get_mcfg_seg()["p_offset"])
        self["mcfg"] = MCFG(
            self._stream, parse_trailer_content=self._parse_trailer_content
        )
        self._parse_mcfg_end()

    @staticmethod
    def _fmt_parsed_content_or_exception(item, p, encoder) -> None:
        try:
            t = item.parse_item_content()
            if t is not None:
                c = json.dumps(t, indent=2, default=encoder.default)
            else:
                c = ""
        except items_generated.NvContentParseError as e:
            c = f"Exception: {repr(_first_implicit_exception(e))}\n"
            c += json.dumps(e.partial, indent=2, default=encoder.default)
        try:
            with open(p, "x") as f:
                write_all(f, c)
        except Exception as e:
            logger.warn(
                f"Exception while trying to parse nv item content: {type(e)}: {e}"
            )

    def extract(self, path):
        """Extract configuration from an MBN file.

        :param path: Where the contents of the MBN file should be extracted to.
        """
        encoder = MbnJsonEncoder(extract_meta=True, indent=2)

        nv_items = []
        path = Path(path)
        files_path = utils.join(Path(path), Path("files"))
        nv_path = utils.join(Path(path), Path("nv"))
        nv_files_path = utils.join(Path(path), Path("parsed_nv_files"))
        nv_path = utils.join(Path(path), Path("parsed_nv_items"))
        nv_path.mkdir(parents=True)
        used_paths = set()
        used_nv_ids = set()
        for item in self["mcfg"]["items"]:
            if item["type"] == MCFG_Item.NV_TYPE:
                name = Path(str(item["nv_id"]))
                free_name = _free_name(name, used_nv_ids)
                used_nv_ids.add(free_name)
                nv_items.append(item)
                Mbn._fmt_parsed_content_or_exception(
                    item, utils.join(nv_path, Path(free_name)), NvContentEncoder()
                )
                continue

            if item["type"] not in [MCFG_Item.NVFILE_TYPE, MCFG_Item.FILE_TYPE]:
                logger.warning(f"Unknown mcfg item type: {item['type']}")
                nv_items.append(item)
                continue

            filename = Path(item["filename"].strip(b"\x00").decode())
            free_name = _free_name(filename, used_paths)
            used_paths.update(free_name.parents, [free_name])

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

            p = utils.join(nv_files_path, filename)
            p.parent.mkdir(parents=True, exist_ok=True)
            Mbn._fmt_parsed_content_or_exception(item, p, NvContentEncoder())

            nv_items.append(item)

        with open(path / "nv_items", "x") as f:
            json.dump(nv_items, f, indent=2, default=encoder.default)
        with open(path / "meta", "x") as f:
            write_all(f, encoder.encode(self["mcfg"]))
        with open(path / "original_file.mbn", "xb") as f:
            self._stream.seek(0)
            buf = self._stream.read()
            write_all(f, buf)

        for item in self["mcfg"]["items"]:
            try:
                del item._header["filename_alias"]
            except KeyError:
                pass

    @staticmethod
    def pack(exdir, path) -> "Mbn":
        """Pack extracted configuration into an MBN file.

        :param exdir: directory containing the extracted configuration.
        :param path: The path of the MBN file to be created.
        """
        exdir = Path(exdir)

        if not all(
            map(
                lambda n: (exdir / n).exists(),
                ["nv_items", "meta", "original_file.mbn", "files"],
            )
        ):
            raise Exception("Extracted file is incomplete!")

        with open(exdir / "meta", "r") as f:
            mcfg = json.load(f, object_hook=decode_hook)

        parse_trailer_content = "data" not in mcfg["trailer"]
        mcfg._parse_trailer_content = parse_trailer_content
        mcfg["trailer"]._parse_trailer_content = parse_trailer_content

        with open(exdir / "nv_items", "r") as f:
            nv_items = json.load(f, object_hook=decode_hook)

        mcfg["items"] = []
        for item in nv_items:
            if item["type"] not in [MCFG_Item.NVFILE_TYPE, MCFG_Item.FILE_TYPE]:
                mcfg["items"].append(item)
                continue

            fp = _extracted_filename(item)
            with open(utils.join(exdir / "files", fp), "rb") as f:
                item["data"] = f.read()

            mcfg["items"].append(item)

        for item in mcfg["items"]:
            try:
                del item._header["filename_alias"]
            except KeyError:
                pass

        stream = open(path, "w+b")
        with open(exdir / "original_file.mbn", "rb") as orig:
            write_all(stream, orig.read())
        stream.seek(0)
        mbn = Mbn.__new__(Mbn)
        mbn._values = {
            "elf": ELFFile(stream),
            "mcfg": mcfg,
        }
        mbn._parse_trailer_content = parse_trailer_content
        mbn.set_stream(stream)
        mbn.rewrite_hashes()
        return mbn

    def get_mcfg_seg(self) -> Segment:
        return self["elf"].get_segment(2)

    def _parse_mcfg_end(self):
        offset = self._stream.tell()

        *_, last_seg = self["elf"].iter_segments()
        mcfg_end = last_seg["p_offset"] + last_seg["p_filesz"]

        if last_seg["p_align"] != 4:
            raise Exception("MCFG segment is not 4-byte aligned.")

        if last_seg["p_filesz"] % 4 != 0:
            raise Exception("Size of MCFG segment is not padded to be a multiple of 4.")

        diff = mcfg_end - offset

        if diff < 0:
            raise Exception("MCFG parser read past MCFG segment end.")

        self._stream.seek(offset - 4)
        end = get_bytes(self._stream, diff + 4)
        padlen = struct.unpack("<I", end[-4:])[0] - self["mcfg"]["trailer"]._item_len

        if padlen <= 0 or padlen >= 5:
            raise Exception(
                f"Invalid length of MCFG segment padding: {padlen} (should be in the range [1,4])"
            )
        if padlen != diff:
            raise Exception("Padding length is inconsistent with trailer length.")

    def rewrite_hashes(self):
        """Updates the hashes in the MBN hash segment.
        Does NOT touch the signature in the hash segment.
        """
        n, hseg = self._get_hash_segment()
        header = parse_hash_header(BytesIO(hseg.data()))
        dig_size = hashlib.new(header.HASH).digest_size

        hashes = []
        for i, s in enumerate(self["elf"].iter_segments()):
            if i == n:
                hashes.append(b"\x00" * dig_size)
                continue

            hashes.append(hashlib.new(header.HASH, s.data()).digest())
        header.hashes = hashes
        self._stream.seek(hseg["p_offset"])
        header.write(self._stream)

    def check_hashes(self) -> bool:
        """Validates the hashes in the hash segment of the MBN file."""
        n, hash_seg = self._get_hash_segment()
        header = parse_hash_header(BytesIO(hash_seg.data()))
        hashes = header.hashes

        if any(map(lambda i: i != 0, hashes[n])):
            return False

        for i, s in enumerate(self["elf"].iter_segments()):
            if i == n:
                continue

            h = hashlib.new(header.HASH, s.data())

            if hashes[i] != h.digest():
                return False

        return True

    def _get_hash_segment(self) -> tuple[int, Segment]:
        mseg = list(
            filter(
                lambda x: x[1]["p_flags"] & 0x200000 != 0,
                enumerate(self["elf"].iter_segments()),
            )
        )

        if len(mseg) == 0:
            raise Exception("Missing hash segment")
        if len(mseg) > 1:
            raise Exception("Found multiple hash segments")

        return mseg[0]

    def _write_mcfg_padding(self, mcfg_len):
        padding_len = 4 - mcfg_len % 4
        self._stream.seek(-(mcfg_len % 4), os.SEEK_CUR)
        pack("<I", self._stream, self["mcfg"]["trailer"]._item_len + padding_len)

    def write(self):
        """Rewrite the parsed MBN file."""

        if self["elf"].num_segments() != 3:
            raise NotImplementedError("MBN file should contain 3 ELF segments.")

        self._stream.seek(self["elf"].get_segment(2)["p_offset"])
        start = self._stream.tell()
        self["mcfg"].write()
        trl_end = self._stream.tell()
        self._write_mcfg_padding(trl_end - start)
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

    def close(self):
        """Calls `close` on the associated stream."""
        self._stream.close()

    def set_stream(self, stream):
        """Set the stream used for parsing and writing to `stream`."""
        self._stream = stream
        self["mcfg"].set_stream(stream)
        self["elf"] = ELFFile(stream)

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

    return n


def _extracted_filename(item: MCFG_Item) -> Path:
    n = item["filename_alias"] if "filename_alias" in item else item["filename"]
    return Path(n.strip(b"\x00").decode())


def _first_implicit_exception(e: BaseException) -> BaseException:
    while e.__context__ is not None:
        e = e.__context__
    return e
