#!/usr/bin/env python3

import json
import logging
import os
import sys

from pathlib import Path
from typing import Optional

from defusedxml import ElementTree as ET

from mbntools.mbn import Mbn
from mbntools.mcfg import MCFG_Item

logger = logging.getLogger(__name__)

def usage():
    print(f"Usage: {sys.argv[0]} <out-file> <dir>", file=sys.stderr)
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        usage()

    fqdns = {}

    for (dirpath, _, filenames) in os.walk(sys.argv[2]):
        dpath = Path(dirpath)
        for f in filenames:
            if not f.endswith(".mbn"):
                continue

            fp = dpath / f
            fqdn = extract(fp)
            if fqdn is not None:
                fqdns.setdefault(fqdn, []).append(str(fp))
            else:
                fqdns.setdefault("", []).append(str(fp))

    with open(sys.argv[1], "x") as f:
        json.dump(fqdns, f, indent=2)

def extract(path: Path) -> Optional[str]:
    with open(path, "rb") as f:
        mbn = Mbn(f)

    items = list(filter(nonempty_file, mbn["mcfg"].get_file_items(b"/data/iwlan_s2b_config.xml\x00")))

    if len(items) == 0:
        logger.warning(f"Failed to find 'iwlan_s2b_config.xml' in '{path}'.")
        return None

    fqdns = set()
    for i in items:
        data = i["data"]

        assert len(data) != 0 and (data[0] != 7 or len(data) > 1)

        if data[0] == 7:
            data = data[1:]

        try:
            root = ET.fromstring(data.decode())
        except Exception as e:
            logger.warning("Exception occurred trying to parse xml file.", e)
            return None

        names = set(map(lambda e: e.text, root.findall(".//epdg_addr_info/fqdn")))

        if len(names) != 1:
            logger.warning(f"Found multiple/no fqdns in xml file: {names}")

        fqdns.update(names)

    if len(fqdns) > 1:
        logger.error(f"Found multiple fqdns in mbn file: {fqdns}")
        raise NotImplementedError

    return fqdns.pop() if len(fqdns) == 1 else None

def nonempty_file(i: MCFG_Item) -> bool:
    return len(i["data"]) != 0 and (i["data"][0] != 7 or len(i["data"]) > 1)

if __name__ == "__main__":
    main()
