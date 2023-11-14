import enum
import logging
import os

from io import BytesIO

from typing import BinaryIO
from collections.abc import Generator

from mbntools.utils import pack, unpack, get_bytes, write_all
from mbntools.items_generated import NV_ITEMS, EFS_FILES, NvContentParseError

logger = logging.getLogger(__name__)

class MCFG_Item:
    NV_TYPE = 1
    NVFILE_TYPE = 2
    FILE_TYPE = 4

    def __init__(self, stream: BinaryIO):
        self._offset = stream.tell()
        self._stream = stream
        self._header = {}
        self.parse()

    def offset(self) -> int:
        return self._offset

    def parse(self):
        self._offset = self._stream.tell()
        self.parse_header()
        self.parse_content()

    def parse_item_content(self):
        if len(self["data"]) == 0:
            return None

        if self["data"][0] == 7:
            s = BytesIO(self["data"][1:])
        else:
            s = BytesIO(self["data"])

        try:
            if self["type"] == MCFG_Item.NV_TYPE and self["nv_id"] in NV_ITEMS:
                c = NV_ITEMS[self["nv_id"]](s)
                c._rest = s.read()
                return c
            elif self["type"] in [MCFG_Item.NVFILE_TYPE, MCFG_Item.FILE_TYPE] and self["filename"].strip(b'\x00').decode() in EFS_FILES:
                c = EFS_FILES[self["filename"].strip(b'\x00').decode()](s)
                c._rest = s.read()
                return c
            else:
                return None
        except NvContentParseError as e:
            e.partial._rest = s.read()
            raise e

    def parse_header(self):
        self._length, \
        self["type"], \
        self["attributes"], \
        self["reserved"] \
        = unpack("<IBBH", self._stream)

    def parse_content(self):
        if self["type"] == self.NV_TYPE:
            self.parse_nv()
        elif self["type"] == self.NVFILE_TYPE or self["type"] == self.FILE_TYPE:
            self.parse_file()
        else:
            logger.info(f"Unknown item type: {self['type']}")
            self["data"] = get_bytes(self._stream, self._length - 8)

    def parse_nv(self):
        self["nv_id"], \
        clen \
        = unpack("<HH", self._stream)

        if (clen + 4 + 8) != self._length:
            raise Exception("Mismatching item and data lengths in nv entry")

        self["data"] = get_bytes(self._stream, clen)

        if len(self["data"]) > 0:
            self["data_magic"] = self["data"][0]

    def parse_file(self):
        magic, = unpack("<H", self._stream)

        if magic != 1:
            logger.warn(f"Invalid magic value in item file header: {magic} should be 1")

        fnamelen, = unpack("<H", self._stream)
        self["filename"] = get_bytes(self._stream, fnamelen)
        fsmagic, = unpack("<H", self._stream)

        if fsmagic != 2:
            raise Exception("Invalid file size magic value")

        clen, = unpack("<H", self._stream)

        if (clen + 8 + fnamelen + 8) != self._length:
            raise Exception("Mismatching item and data length in file entry")

        self["data"] = get_bytes(self._stream, clen)

        if len(self["data"]) > 0:
            self["data_magic"] = self["data"][0]

    def write(self):
        self._offset = self._stream.tell()
        self._stream.seek(4, os.SEEK_CUR)
        pack("<BBH", self._stream,
             self["type"],
             self["attributes"],
             self["reserved"],
             )

        if self["type"] == self.NV_TYPE:
            self._write_nv()
        elif self["type"] == self.NVFILE_TYPE or self["type"] == self.FILE_TYPE:
            self._write_file()
        else:
            self._write_unknown_type()

        end = self._stream.tell()
        length = end - self._offset
        self._stream.seek(self._offset)
        pack("<I", self._stream, length)
        self._stream.seek(end)

    def _write_unknown_type(self):
        if len(self["data"]) >= 2**16 - 8:
            raise Exception("Item content is longer than the allowed (2**16 - 9) byte maximum.")

        write_all(self._stream, self["data"])

    def _write_file(self):
        if len(self["filename"]) >= 2**16:
            raise Exception(f"Filename is too long: {len(self['filename'])} (max: {2**16 - 1})")
        if len(self["data"]) >= 2**16:
            raise Exception("Item content is longer than the allowed (2**16 - 1) byte maximum.")

        pack("<HH", self._stream, 1, len(self["filename"]))
        write_all(self._stream, self["filename"])
        pack("<HH", self._stream, 2, len(self["data"]))
        write_all(self._stream, self["data"])

    def _write_nv(self):
        if len(self["data"]) >= 2**16:
            raise Exception("Item content is longer than the allowed (2**16 - 1) byte maximum.")

        pack("<HH", self._stream,
             self["nv_id"],
             len(self["data"]),
             )
        write_all(self._stream, self["data"])

    def _set_stream(self, stream):
        self._stream = stream

    def __getitem__(self, k):
        return self._header[k]

    def __setitem__(self, k, v):
        self._header[k] = v

    def __contains__(self, k):
        return k in self._header

class MCFG_Trailer:
    def __init__(self, stream: BinaryIO, parse_trailer_content=True):
        self._offset = stream.tell()
        self._stream = stream
        self._header = {}
        self._parse_trailer_content = parse_trailer_content
        self.parse()

    def offset(self) -> int:
        return self._offset

    def parse(self):
        self._offset = self._stream.tell()
        self._parse_header()
        if self._parse_trailer_content:
            self._parse_content()
        else:
            self["data"] = get_bytes(self._stream, self._item_len - 10)

    def _parse_header(self):
        self._item_len, \
        magic, \
        self["reserved"], \
        magic2, \
        = unpack("<IHHH", self._stream)

        if magic != 10:
            raise Exception(f"Invalid item type for trailer item: {magic}")

        if magic2 != 0xa1:
            raise Exception(f"Invalid reserved field for trailer item: {magic2}")

    def _parse_trl_item(self):
        opcode, l = unpack("<BH", self._stream)

        try:
            opcode = TrlOpcode(opcode)
        except ValueError:
            logger.debug(f"Unknown trailer opcode {opcode}: " + get_bytes(self._stream, l).hex(' ', 1))
            return

        assert opcode not in self, "duplicate opcode"
        if opcode == TrlOpcode.mnoid or opcode == TrlOpcode.iccids:
            unknown_field, nids = unpack("<BB", self._stream)

            assert l == nids * 4 + 2, f"{opcode.name}: {l} != {nids} * 4 + 2 ({nids * 4 + 2})"

            self[opcode.name] = {"ids": [], "unknown_field": unknown_field}
            for _ in range(nids):
                if opcode == TrlOpcode.mnoid:
                    mcc, mnc = unpack("<HH", self._stream)

                    if opcode == TrlOpcode.mnoid:
                        self[opcode.name]["ids"].append(MnoId(mcc, mnc))
                    else:
                        self[opcode.name]["ids"].append((mcc, mnc))
                else:
                    self[opcode.name]["ids"].append(unpack("<I", self._stream)[0])
        else:
            self[opcode.name] = get_bytes(self._stream, l)

        if opcode == TrlOpcode.start and self[opcode.name] != b"\x00\x01":
            logger.warn(f"TRL op 00 {self[opcode.name]} != b'\\x00\\x01'")
        elif opcode == TrlOpcode.version2 and self[opcode.name] != self[TrlOpcode.version1.name]:
            logger.info("MCFG Trailer contains two differing versions")

    def _parse_content(self):
        clen, = unpack("<H", self._stream)
        pos = self._stream.tell()

        magic = get_bytes(self._stream, 8)

        if magic != b"MCFG_TRL":
            raise Exception(f"Invalid trailer magic value: {magic}")

        while self._stream.tell() < pos + clen:
            self._parse_trl_item()

        missing = (self._offset + self._item_len) - self._stream.tell()
        if missing != 4: \
            raise Exception( f"Invalid trailer record size or missing padding \
                (unconsumed trailer record bytes: {missing})")
        get_bytes(self._stream, missing)

    def write(self):
        self._write_header()

        if self._parse_trailer_content:
            pack("<H", self._stream, self._item_len - 12 - 4)
            write_all(self._stream, b"MCFG_TRL")

            self._write_trl_items()

            write_all(self._stream, b'\x00' * 4)
        else:
            write_all(self._stream, self["data"])

    def _write_trl_items(self):
        for c in TrlOpcode:
            if c.name not in self:
                continue

            if c == TrlOpcode.mnoid or c == TrlOpcode.iccids:
                pack("<BH", self._stream, c.value, len(self[c.name]["ids"]) * 4 + 2)
                pack("<BB", self._stream, self[c.name]["unknown_field"], len(self[c.name]["ids"]))
                for o in self[c.name]["ids"]:
                    if c == TrlOpcode.mnoid:
                        pack("<HH", self._stream, o.mcc, o.mnc)
                    else:
                        pack("<I", self._stream, o)
                continue

            pack("<BH", self._stream, c.value, len(self[c.name]))
            write_all(self._stream, self[c.name])

    def _write_header(self):
        self._offset = self._stream.tell()
        self._item_len = self._calc_item_len()

        if self._item_len >= 10**32:
            raise Exception("MCFG_Trailer content is too long: {len(self['data'])} (>10**32-1)")

        pack("<IHHH", self._stream, self._item_len, 10, self["reserved"], 0xa1)

    def _calc_item_len(self):
        if not self._parse_trailer_content:
            return 10 + len(self["data"])

        l = 20
        for c in TrlOpcode:
            if c.name not in self:
                continue

            if c == TrlOpcode.mnoid or c == TrlOpcode.iccids:
                l += len(self[c.name]["ids"]) * 4 + 5
                continue
            l += len(self[c.name]) + 3
        l += 4 # padding
        return l

    def _set_stream(self, stream):
        self._stream = stream

    def __getitem__(self, k):
        return self._header[k]

    def __setitem__(self, k, v):
        self._header[k] = v

    def __delitem__(self, k):
        del self._header[k]

    def __contains__(self, k):
        return k in self._header

class MCFG:
    def __init__(self, stream: BinaryIO, parse_trailer_content=True):
        self._offset = stream.tell()
        self._stream = stream
        self._header: dict = {}
        self._parse_trailer_content = parse_trailer_content
        self.parse()

    def offset(self) -> int:
        return self._offset

    def parse(self):
        self._offset = self._stream.tell()
        self._parse_header()
        self._parse_items()
        self._parse_trailer()

    def _parse_header(self):
        magic = get_bytes(self._stream, 4)
        if magic != b"MCFG":
            raise Exception(f"Invalid Magic value: {magic} should be b'MCFG'")

        # reserved: spare_crc
        self["format_type"], \
        self["configuration_type"], \
        self._items_count, \
        self["carrier_index"], \
        self["reserved"], \
        self["version_id"], \
        version_size \
        = unpack("<HHIHHHH", self._stream)

        try:
            self["configuration_type"] = ["hw", "sw"][self["configuration_type"]]
        except IndexError:
            raise Exception("Unknown configuration type")

        if self["version_id"] != 4995:
            raise Exception("Unknown version")

        self["version"] = get_bytes(self._stream, version_size)

    def _parse_items(self):
        self["items"] = []
        for _ in range(self._items_count - 1): # The last item is special and treated separately
            item = MCFG_Item(self._stream)
            self["items"].append(item)

    def _parse_trailer(self):
        self["trailer"] = MCFG_Trailer(self._stream, parse_trailer_content=self._parse_trailer_content)

    def remove_filename(self, name: bytes) -> None:
        self["items"] = list(filter(lambda i: "filename" not in i or i["filename"].strip(b'\x00') != name.strip(b'\x00'), self["items"])) # pyright: ignore [reportGeneralTypeIssues]

    def remove_nv_id(self, nvid: int) -> None:
        self["items"] = list(filter(lambda i: "nv_id" not in i or i["nv_id"] != nvid, self["items"])) # pyright: ignore [reportGeneralTypeIssues]

    def filenames(self) -> Generator[bytes, None, None]:
        for i in self["items"]:
            if "filename" in i:
                yield i["filename"]

    def nv_ids(self) -> Generator[int, None, None]:
        for i in self["items"]:
            if "nv_id" in i:
                yield i["nv_id"]

    def get_file_items(self, name: bytes) -> list[MCFG_Item]:
        return list(filter(lambda i: "filename" in i and name == i["filename"], self["items"]))

    def get_nv_items(self, nvid: int) -> list[MCFG_Item]:
        return list(filter(lambda i: "nv_id" in i and nvid == i["nv_id"], self["items"]))

    def _find_filepath(self, path: bytes) -> list[MCFG_Item]:
        def cmp_path(x, y):
            if not "filename" in x:
                return False

            t = x["filename_alias"] if "filename_alias" in x else x["filename"]
            return t.strip(b'\x00') == y.strip(b'\x00')

        return list(filter(lambda x: cmp_path(x, path), self["items"]))

    def write(self):
        self._offset = self._stream.tell()
        self._write_header()
        for item in self["items"]:
            item.write()
        self["trailer"].write()

    def _write_header(self):
        if len(self["items"]) >= 2**32:
            raise Exception("Too many items (>2**32-2)")
        if len(self["version"]) >= 2**16:
            raise Exception("Version is too long (>2**16-1)")
        if self["configuration_type"] not in ["hw", "sw"]:
            raise Exception(f"Illegal configuration type: {self['configuration_type']}")

        write_all(self._stream, b"MCFG")
        pack("<HHIHHHH", self._stream,
             self["format_type"],
             0 if self["configuration_type"] == "hw" else 1,
             len(self["items"]) + 1,
             self["carrier_index"],
             self["reserved"],
             self["version_id"],
             len(self["version"]),
             )
        write_all(self._stream, self["version"])

    def _set_stream(self, stream):
        self._stream = stream
        for i in self["items"]:
            i._set_stream(stream)
        self["trailer"]._set_stream(stream)

    def __getitem__(self, k):
        return self._header[k]

    def __setitem__(self, k, v):
        self._header[k] = v

    def __contains__(self, k):
        return k in self._header

class MnoId:
    def __init__(self, mcc: int, mnc: int):
        self.mcc = mcc
        self.mnc = mnc

    def __str__(self) -> str:
        return f"MnoId(mcc: {self.mcc}, MNC: {self.mnc})"

    def __repr__(self) -> str:
        return f"MnoId({self.mcc}, {self.mnc})"

@enum.unique
class TrlOpcode(enum.Enum):
    start = 0
    version1 = 1
    unknown1 = 2 # APPLICABLE_MCC_MNC (https://github.com/Biktorgj/mcfg_tools/blob/e1293b557ec58e535522f151f765f757d9f93af5/mcfg.h#L250C3-L250C41)
    operator = 3
    iccids = 4
    version2 = 5
    mnoid = 6
    unknown2 = 7
    checksum = 8
    end = 9
