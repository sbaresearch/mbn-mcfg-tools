#!/usr/bin/env python3

import json
import logging
import os
import sys
import re

from pathlib import Path
from typing import List, Optional

from defusedxml import ElementTree as ET

from mbn_mcfg_tools.mbn import Mbn
from mbn_mcfg_tools.mcfg import MCFG_Item

logger = logging.getLogger(__name__)

REGEX_VOWIFI = "^epdg.epc.mnc(\d{2,3}).mcc(\d{3}).pub.3gppnetwork.org\.?$"
def is_3gpp_vowifi_domain(host):
    return re.search(REGEX_VOWIFI, host)

def create_3gpp_vowifi_domain(mcc, mnc):
    return f"epdg.epc.mnc{mnc:03d}.mcc{mcc:03d}.pub.3gppnetwork.org"

#epdg.epc.mnc027.mcc208.pub.3gppnetwork.org. CNAME epdgc.epc.mnc027.mcc208.pub.3gppnetwork.org.

def usage():
    print(f"Usage: {sys.argv[0]} <out-file> <dir>", file=sys.stderr)
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        usage()

    fqdns = {}
    cname_mapping = []

    for (dirpath, _, filenames) in os.walk(sys.argv[2]):
        dpath = Path(dirpath)
        for f in filenames:
            if not f.endswith(".mbn"):
                continue

            fp = dpath / f

            # build json
            fqdn = extract_iwlan_fqdns(fp)
            if fqdn is not None:
                fqdns.setdefault(fqdn, []).append(str(fp))
            else:
                fqdns.setdefault("", []).append(str(fp))
            
            # build cname mapping
            cname_mapping.extend(extract_cname_mapping(fp))

    # dump json
    with open(f"{sys.argv[1]}.json", "x") as f:
        json.dump(fqdns, f, indent=2)

    # dump list
    with open(f"{sys.argv[1]}.txt", "x") as f:
        f.writelines(line + '\n' for line in cname_mapping)

def extract_iwlan_fqdns_from_mbn(path: Path, mbn: Mbn) -> Optional[str]:
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

def extract_iwlan_fqdns(path: Path) -> Optional[str]:
    with open(path, "rb") as f:
        mbn = Mbn(f)
    return extract_iwlan_fqdns_from_mbn(path, mbn)
     

def generate_cname_mapping_for_fqdns(mbn: Mbn, fqdns: str) -> List[str]:
    cname_mapping = []
    mnoids = mbn["mcfg"]["trailer"]["mnoid"].get('ids',[])
    for d in mnoids:
        standardized_domain = create_3gpp_vowifi_domain(d.mcc, d.mnc)
        cname_mapping.append(f"{standardized_domain} CNAME {fqdns}")
    return cname_mapping

def extract_cname_mapping(path: Path) -> List[str]:
    with open(path, "rb") as f:
        mbn = Mbn(f)
    fqdns = extract_iwlan_fqdns_from_mbn(path, mbn)
    if fqdns is not None:
        if not is_3gpp_vowifi_domain(fqdns):
            return generate_cname_mapping_for_fqdns(mbn, fqdns)
        else:
            logger.warning(f"Ignore 3gpp standardized fqdns {fqdns}")
    return []
    

def nonempty_file(i: MCFG_Item) -> bool:
    return len(i["data"]) != 0 and (i["data"][0] != 7 or len(i["data"]) > 1)

if __name__ == "__main__":
    main()
