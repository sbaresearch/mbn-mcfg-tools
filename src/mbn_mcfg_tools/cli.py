#!/usr/bin/env python3

import argparse
from pathlib import Path
import sys

from mbn_mcfg_tools.mbn import Mbn

import logging

logging.basicConfig(level=logging.INFO)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--check",
        metavar="FILE",
        help="Check the hashes in the secure boot header. "
        "Does NOT check the signature.",
    )
    parser.add_argument(
        "-e",
        "--extract",
        metavar="FILE",
        help="Extract configuration to [extraction_dir].",
    )
    parser.add_argument(
        "-p",
        "--pack",
        metavar="FILE",
        help="Pack configuration in [extraction_dir] into %(metavar)s.",
    )
    parser.add_argument(
        "-t",
        "--no-parse-trailer",
        action="store_false",
        dest="parse_trailer",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "extraction_dir",
        nargs="?",
        help="Directory that configuration should be extracted to or read from. "
        "Defaults to the filename given by either --extract or --pack with the suffix '_extracted'."
    )

    args = parser.parse_args()

    if args.check is None and args.extract is None and args.pack is None:
        parser.print_help()
        sys.exit(1)

    if args.extraction_dir is None:
        name = args.extract or args.pack
        if name is not None:
            args.extraction_dir = Path(name).stem + "_extracted"

    if args.extract is not None:
        print(f"Extracting {args.extract} to {args.extraction_dir}...", file=sys.stderr)
        extract(args.extract, args.extraction_dir, args.parse_trailer)

    if args.pack is not None:
        print(f"Packing {args.extraction_dir} into {args.pack}...", file=sys.stderr)
        pack(args.extraction_dir, args.pack)

    if args.check is not None:
        with open(args.check, "rb") as f:
            print(f"Checking hashes in file {args.check}...", file=sys.stderr, end="")
            mbn = Mbn(f)
            if mbn.check_hashes():
                print(" passed", file=sys.stderr)
            else:
                print(" failed", file=sys.stderr)


def extract(path, exdir, parse_trailer):
    with open(path, "rb") as f:
        mbn = Mbn(f, parse_trailer_content=parse_trailer)
        mbn.extract(exdir)


def pack(exdir, path):
    mbn = Mbn.pack(exdir, path)
    mbn.write()
    mbn.rewrite_hashes()
    mbn._stream.close()


if __name__ == "__main__":
    main()
