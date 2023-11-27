import hashlib

from typing import BinaryIO

from mbn_mcfg_tools.utils import unpack, pack

# format from https://github.com/msm8916-mainline/qtestsign/blob/9ed0787b76b911b346b6dcd0b94093fcf53ff91f/fw/hashseg.py


class HashSegHeader:
    HASH = "sha256"

    def __init__(self):
        self.hash_size = 0
        self._data = b""

    @property
    def hashes(self) -> list[bytes]:
        digest_size = hashlib.new(self.HASH).digest_size
        offset = getattr(self, "metadata_size_qcom", 0) + getattr(
            self, "metadata_size", 0
        )
        hash_table = self._data[offset : offset + self.hash_size]
        assert self.hash_size % digest_size == 0

        hashes = []
        for i in range(self.hash_size // digest_size):
            hashes.append(hash_table[i * digest_size : (i + 1) * digest_size])
        return hashes

    @hashes.setter
    def hashes(self, value: list[bytes]) -> None:
        digest_size = hashlib.new(self.HASH).digest_size

        if len(value) * digest_size != self.hash_size:
            raise NotImplementedError  # TODO

        offset = getattr(self, "metadata_size_qcom", 0) + getattr(
            self, "metadata_size", 0
        )
        self._data = (
            self._data[:offset]
            + b"".join(value)
            + self._data[offset + self.hash_size :]
        )

    def write(self, _: BinaryIO) -> None:
        raise NotImplementedError


class HashSegHeaderV3(HashSegHeader):
    HEADER_SIZE = 40
    HASH = "sha256"

    def __init__(self, stream: BinaryIO):
        self._parse(stream)

    def _parse(self, stream: BinaryIO) -> None:
        (
            self.image_id,
            self.version,
            self.flash_addr,
            self.dest_addr,
            self.total_size,
            self.hash_size,
            self.signature_addr,
            self.signature_size,
            self.cert_chain_addr,
            self.cert_chain_size,
        ) = unpack("<10I", stream)
        self._data = stream.read()

    def write(self, stream: BinaryIO) -> None:
        pack(
            "<10I",
            stream,
            self.image_id,
            self.version,
            self.flash_addr,
            self.dest_addr,
            self.total_size,
            self.hash_size,
            self.signature_addr,
            self.signature_size,
            self.cert_chain_addr,
            self.cert_chain_size,
        )
        stream.write(self._data)


class HashSegHeaderV5(HashSegHeader):
    HEADER_SIZE = 40
    HASH = "sha256"

    def __init__(self, stream: BinaryIO):
        self._parse(stream)

    def _parse(self, stream: BinaryIO) -> None:
        (
            self.image_id,
            self.version,
            self.signature_size_qcom,
            self.cert_chain_size_qcom,
            self.total_size,
            self.hash_size,
            self.signature_addr,
            self.signature_size,
            self.cert_chain_addr,
            self.cert_chain_size,
        ) = unpack("<10I", stream)
        self._data = stream.read()

    def write(self, stream: BinaryIO) -> None:
        pack(
            "<12I",
            stream,
            self.image_id,
            self.version,
            self.signature_size_qcom,
            self.cert_chain_size_qcom,
            self.total_size,
            self.hash_size,
            self.signature_addr,
            self.signature_size,
            self.cert_chain_addr,
            self.cert_chain_size,
        )
        stream.write(self._data)


class HashSegHeaderV6(HashSegHeader):
    HEADER_SIZE = 48
    HASH = "sha384"

    def __init__(self, stream: BinaryIO) -> None:
        self._parse(stream)

    def _parse(self, stream: BinaryIO) -> None:
        (
            self.image_id,
            self.version,
            self.signature_size_qcom,
            self.cert_chain_size_qcom,
            self.total_size,
            self.hash_size,
            self.signature_addr,
            self.signature_size,
            self.cert_chain_addr,
            self.cert_chain_size,
            self.metadata_size_qcom,
            self.metadata_size,
        ) = unpack("<12I", stream)
        self._data = stream.read()

    def write(self, stream: BinaryIO) -> None:
        pack(
            "<12I",
            stream,
            self.image_id,
            self.version,
            self.signature_size_qcom,
            self.cert_chain_size_qcom,
            self.total_size,
            self.hash_size,
            self.signature_addr,
            self.signature_size,
            self.cert_chain_addr,
            self.cert_chain_size,
            self.metadata_size_qcom,
            self.metadata_size,
        )
        stream.write(self._data)


def parse_hash_header(stream: BinaryIO) -> HashSegHeader:
    p = stream.tell()
    _, version = unpack("<2I", stream)
    stream.seek(p)

    match version:
        case 3:
            return HashSegHeaderV3(stream)
        case 5:
            return HashSegHeaderV5(stream)
        case 6:
            return HashSegHeaderV6(stream)
        case _:
            raise Exception(f"Unknown hash segment header version: {version}")
