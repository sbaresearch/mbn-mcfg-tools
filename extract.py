#!/usr/bin/env python3

import argparse
import sys

from mbntools.mbn import Mbn

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--check")
    parser.add_argument("-e", "--extract")
    parser.add_argument("-p", "--pack")
    parser.add_argument("extraction_dir", nargs="?", default="extracted")

    args = parser.parse_args()

    if args.extract is not None:
        print(f"Extracting {args.extract} to {args.extraction_dir}...", file=sys.stderr)
        extract(args.extract, args.extraction_dir)

    if args.pack is not None:
        print(f"Packing {args.extraction_dir} into {args.pack}...", file=sys.stderr)
        pack(args.extraction_dir, args.pack)

    if args.check is not None:
        with open(args.check, "rb") as f:
            print(f"Checking hashes in file {args.check}...", file=sys.stderr, end="")
            mbn = Mbn(f)
            if mbn.check_hashes():
                print(f" passed", file=sys.stderr)
            else:
                print(f" failed", file=sys.stderr)


def extract(path, exdir):
    with open(path, "rb") as f:
        mbn = Mbn(f)
        mbn.extract(exdir)

def pack(exdir, path):
    mbn = Mbn.unextract(exdir, path)
    mbn.write()
    mbn.rewrite_hashes()
    mbn._stream.close()

if __name__ == "__main__":
    main()
