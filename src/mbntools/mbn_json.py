import json

from mbntools.mcfg import MCFG, MCFG_Item, MCFG_Trailer, MnoId

class MbnJsonEncoder(json.JSONEncoder):
    def __init__(self, *args, extract_meta=False, **kwargs):
        self._extract_meta = extract_meta
        super().__init__(*args, **kwargs)

    def default(self, o):
        if isinstance(o, bytes):
            r = {
                "hex": o.hex(' ', -1),
                "ascii": o.decode("ascii", errors="replace").replace('\ufffd', '.'),
                }
        elif isinstance(o, MCFG_Item):
            r = o._header.copy()
            if self._extract_meta and o["type"] != MCFG_Item.NV_TYPE:
                del r["data"]
        elif isinstance(o, MCFG_Trailer):
            r = o._header
        elif isinstance(o, MCFG):
            if self._extract_meta:
                r = o._header.copy()
                del r["items"]
            else:
                r = o._header
        elif isinstance(o, MnoId):
            r = {
                "mcc": o.mcc,
                "mnc": o.mnc,
                }
        else:
            return super().default(o)
        r["__type__"] = type(o).__name__ # pyright: ignore
        return r

def decode_hook(o):
    if "__type__" not in o:
        return o

    if o["__type__"] == bytes.__name__:
        return bytes.fromhex(o["hex"])

    if o["__type__"] == MnoId.__name__:
        return MnoId(o["mcc"], o["mnc"])

    if o["__type__"] not in [MCFG_Item.__name__, MCFG_Trailer.__name__, MCFG.__name__]:
        return o

    cls = globals()[o["__type__"]]
    r = cls.__new__(cls)
    del o["__type__"]
    r._header = o

    return r
