import io
import os
import logging

from typing import Optional

from mbntools.utils import pack, unpack, get_bytes, write_all

logger = logging.getLogger(__name__)

class MCFG_Item:
    NV_TYPE = 1
    NVFILE_TYPE = 2
    FILE_TYPE = 4

    def __init__(self, stream):
        self._offset = None
        self.stream = stream
        self.header = {}

    def offset(self) -> Optional[int]:
        return self._offset

    def parse(self):
        self._offset = self.stream.tell()
        self.parse_header()
        self.parse_content()

    def parse_header(self):
        self["length"], \
        self["type"], \
        self["attributes"], \
        self["reserved"] \
        = unpack("<IBBH", self.stream)

    def parse_content(self):
        if self["type"] == self.NV_TYPE:
            self.parse_nv()
        elif self["type"] == self.NVFILE_TYPE or self["type"] == self.FILE_TYPE:
            self.parse_file()
        else:
            raise Exception(f"Unknown item type: {self['type']}")

    def parse_nv(self):
        self["nv_id"], \
        clen \
        = unpack("<HH", self.stream)

        if (clen + 4 + 8) != self["length"]:
            raise Exception("Mismatching item and data lengths in nv entry")

        self["data"] = get_bytes(self.stream, clen)

        if len(self["data"]) > 0:
            self["data_magic"] = self["data"][0]

    def parse_file(self):
        magic, = unpack("<H", self.stream)

        if magic != 1:
            logger.warn(f"Invalid magic value in item file header: {magic} should be 1")

        fnamelen, = unpack("<H", self.stream)
        self["filename"] = get_bytes(self.stream, fnamelen)
        fsmagic, = unpack("<H", self.stream)

        if fsmagic != 2:
            raise Exception("Invalid file size magic value")

        clen, = unpack("<H", self.stream)

        if (clen + 8 + fnamelen + 8) != self["length"]:
            raise Exception("Mismatching item and data length in file entry")

        self["data"] = get_bytes(self.stream, clen)

        if len(self["data"]) > 0:
            self["data_magic"] = self["data"][0]

    def write(self):
        self._offset = self.stream.tell()
        self.stream.seek(4, os.SEEK_CUR)
        pack("<BBH", self.stream,
             self["type"],
             self["attributes"],
             self["reserved"],
             )

        if self["type"] == self.NV_TYPE:
            self._write_nv()
        elif self["type"] == self.NVFILE_TYPE or self["type"] == self.FILE_TYPE:
            self._write_file()

        end = self.stream.tell()
        length = end - self._offset
        self.stream.seek(self._offset)
        pack("<I", self.stream, length)
        self.stream.seek(end)

    def _write_file(self):
        if len(self["filename"]) >= 2**16:
            raise Exception(f"Filename is too long: {len(self['filename'])} (max: {2**16 - 1})")
        if len(self["data"]) >= 2**16:
            raise Exception("Item content is longer than the allowed (2**16 - 1) byte maximum.")

        pack("<HH", self.stream, 1, len(self["filename"]))
        write_all(self.stream, self["filename"])
        pack("<HH", self.stream, 2, len(self["data"]))
        write_all(self.stream, self["data"])

    def _write_nv(self):
        if len(self["data"]) >= 2**16:
            raise Exception("Item content is longer than the allowed (2**16 - 1) byte maximum.")

        pack("<HH", self.stream,
             self["nv_id"],
             len(self["data"]),
             )
        write_all(self.stream, self["data"])

    def __getitem__(self, k):
        return self.header[k]

    def __setitem__(self, k, v):
        self.header[k] = v

class MCFG_Trailer:
    def __init__(self, stream):
        self.stream = stream
        self.header = {}

    def parse(self):
        self._parse_header()
        self["data"] = get_bytes(self.stream, self.item_len - 10)
        logger.debug(f"Position after parsing trailer: {self.stream.tell()}")

    def parse_content(self):
        self.parse()
        stream = io.BytesIO(self["data"])
        self._parse_content(stream)

    def _parse_header(self):
        self.item_len, \
        magic, \
        self["reserved"], \
        magic2, \
        = unpack("<IHHH", self.stream)

        if magic != 10:
            raise Exception(f"Invalid item type for trailer item: {magic}")

        if magic2 != 0xa1:
            raise Exception(f"Invalid reserved field for trailer item: {magic2}")

    def _parse_content(self, stream):
        clen, = unpack("<H", stream)
        pos = stream.tell()

        magic = get_bytes(stream, 8)

        if magic != b"MCFG_TRL":
            raise Exception(f"Invalid trailer magic value: {magic}")

        self["unknown1"] = get_bytes(stream, 6)
        vlen, = unpack("<H", stream)

        if vlen != 4: logger.debug(f"Version length: {vlen}")

        self["version"] = get_bytes(stream, vlen)
        self["ub1"] = get_bytes(stream, 1)
        plen, = unpack("<H", stream)
        self["provider_id"] = get_bytes(stream, plen)
        self["ub2"] = get_bytes(stream, 1)
        unknown_len, = unpack("<H", stream)
        self["unknown2"] = get_bytes(stream, unknown_len)
        self["ub3"] = get_bytes(stream, 1)

        self["potential_version2_len"], = unpack("<H", stream)
        self["version2"] = get_bytes(stream, vlen)

        self["unknown3"] = get_bytes(stream, 4)
        idlen, = unpack("<B", stream)

        self["network_ids"] = []
        for _ in range(idlen):
            self["network_ids"].append(unpack("<HH", stream)) # MCC/MNC

        unconsumed = clen - (idlen * 4 + 30 + unknown_len + plen + vlen + vlen)
        self["unknown4"] = get_bytes(stream, unconsumed)
        if unconsumed < 0:
            logger.warn(f"Read past the end of the trailer content")
        assert stream.tell() - pos == clen
        #assert clen + 12 == self.item_len, f"len mismatch {(clen + 12) - self.item_len}"

    def write(self):
        if len(self["data"]) + 10 >= 10**32:
            raise Exception("MCFG_Trailer content is too long: {len(self['data'])} (>10**32-1)")

        pack("<IHHH", self.stream, len(self["data"]) + 10, 10, self["reserved"], 0xa1)
        write_all(self.stream, self["data"])

    def __getitem__(self, k):
        return self.header[k]

    def __setitem__(self, k, v):
        self.header[k] = v

class MCFG:
    def __init__(self, stream):
        self.stream = stream
        self.header: dict = {}

    def parse(self):
        self._parse_header()
        self._parse_items()
        self._parse_trailer()

    def _parse_header(self):
        magic = get_bytes(self.stream, 4)
        if magic != b"MCFG":
            raise Exception(f"Invalid Magic value: {magic} should be b'MCFG'")

        self["format_type"], \
        self["configuration_type"], \
        self["items_count"], \
        self["carrier_index"], \
        self["reserved"], \
        self["version_id"], \
        version_size \
        = unpack("<HHIHHHH", self.stream)

        try:
            self["configuration_type"] = ["hw", "sw"][self["configuration_type"]]
        except IndexError:
            raise Exception("Unknown configuration type")

        if self["version_id"] != 4995:
            raise Exception("Unknown version")

        self["version"] = get_bytes(self.stream, version_size)

    def _parse_items(self):
        self["items"] = []
        for _ in range(self["items_count"] - 1): # The last item is special and treated separately
            item = MCFG_Item(self.stream)
            item.parse()
            self["items"].append(item)

    def _parse_trailer(self):
        self["trailer"] = MCFG_Trailer(self.stream)
        self["trailer"].parse()

    def write(self):
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

        write_all(self.stream, b"MCFG")
        pack("<HHIHHHH", self.stream,
             self["format_type"],
             0 if self["configuration_type"] == "hw" else 1,
             len(self["items"]) + 1,
             self["carrier_index"],
             self["reserved"],
             self["version_id"],
             len(self["version"]),
             )
        write_all(self.stream, self["version"])

    def __getitem__(self, k):
        return self.header[k]

    def __setitem__(self, k, v):
        self.header[k] = v
