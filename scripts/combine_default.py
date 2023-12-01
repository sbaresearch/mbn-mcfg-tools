#!/usr/bin/env python3

import sys
import shutil

from pathlib import Path
from typing import Optional
from io import BytesIO

from mbn_mcfg_tools.mbn import Mbn
from mbn_mcfg_tools.mcfg import MCFG, MCFG_Item

# TODO: search for duplicate items in SW_DEFAULT


def is_empty_item(item: MCFG_Item) -> bool:
    if "data" not in item:
        return True

    if len(item["data"]) == 0:
        return True

    i = 1 if item["data"][0] == 7 else 0
    if all(map(lambda x: x == 0, item["data"][i:])):
        return True

    return False


def find_mcfg_sw_default(hlos: bytes) -> Optional[MCFG]:
    i = hlos.find(b"MCFG")

    while i != -1:
        if hlos[i : i + 7] in [b"MCFG_TR", b"MCFG_HW", b"MCFG_SW"]:
            i = hlos.find(b"MCFG", i + 1)
            continue

        try:
            mcfg = MCFG(BytesIO(hlos[i:]))
            if mcfg["trailer"]["operator"] == b"SW_DEFAULT":
                return mcfg
        except Exception:
            pass
        i = hlos.find(b"MCFG", i + 1)

    return None


def usage():
    print(f"Usage: {sys.argv[0]} <HLOS file> <mbn> <out>", file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 4:
        usage()

    hlos_p = Path(sys.argv[1])
    mbn_p = Path(sys.argv[2])
    out_p = Path(sys.argv[3])

    if out_p.exists():
        print(f"{out_p} already exists", file=sys.stderr)
        sys.exit(2)

    if not mbn_p.is_file():
        print(f"{mbn_p} is not a file or does not exist.", file=sys.stderr)
        sys.exit(2)

    if not hlos_p.is_file():
        print(f"{hlos_p} is not a file or does not exist.", file=sys.stderr)
        sys.exit(2)

    with open(hlos_p, "rb") as f:
        mcfg = find_mcfg_sw_default(f.read())

    if mcfg is None:
        print("Couldn't find SW_DEFAULT MCFG segment", sys.stderr)
        sys.exit(3)

    shutil.copyfile(mbn_p, out_p)

    with open(out_p, "r+b") as f:
        mbn = Mbn(f)

        default_files = set(mcfg.filenames()) - set(mbn["mcfg"].filenames())
        default_nvs = set(mcfg.nv_ids()) - set(mbn["mcfg"].nv_ids())
        print(f"Adding default files: {default_files}")
        print(f"Adding default NV items: {default_nvs}")

        mbn["mcfg"]["items"].extend(
            [f for n in default_files for f in mcfg.get_file_items(n)]
        )
        mbn["mcfg"]["items"].extend(
            [nv for n in default_nvs for nv in mcfg.get_nv_items(n)]
        )

        mbn.set_stream(f)
        mbn.write()
        mbn.rewrite_hashes()


if __name__ == "__main__":
    main()
