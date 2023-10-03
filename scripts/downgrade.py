#!/usr/bin/env python3

import sys
import shutil

from mbntools.mbn import Mbn

import logging

def usage():
    print(f"Usage: {sys.argv[0]} <src> <dst>", file=sys.stderr)
    sys.exit(1)

def downgraded_version(version):
    return version[:-1] + b'\x05'

def main():
    if len(sys.argv) != 3:
        usage()

    shutil.copyfile(sys.argv[1], sys.argv[2])

    with open(sys.argv[2], "r+b") as f:
        mbn = Mbn(f)
        mbn["mcfg"]["format_type"] = 3
        mbn["mcfg"]["version"] = downgraded_version(mbn["mcfg"]["version"])
        mbn["mcfg"]["trailer"]["version1"] = downgraded_version(mbn["mcfg"]["trailer"]["version1"])
        mbn["mcfg"]["trailer"]["version2"] = downgraded_version(mbn["mcfg"]["trailer"]["version2"])

        try:
            del mbn["mcfg"]["trailer"]["checksum"]
        except KeyError:
            logging.info("Trailer does not contain 'checksum' field.")
        try:
            del mbn["mcfg"]["trailer"]["end"]
        except KeyError:
            logging.info("Trailer does not contain 'end' field.")

        mbn.write()
        mbn.rewrite_hashes()

if __name__ == "__main__":
    main()
