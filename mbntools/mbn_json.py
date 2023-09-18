import json

import mbntools.mcfg
from mbntools.mcfg import *

class MbnJsonEncoder(json.JSONEncoder):
    def __init__(self, *args, partial=False, **kwargs):
        self._partial = partial
        super().__init__(*args, **kwargs)

    def default(self, o):
        if isinstance(o, bytes):
            return {
                "__type__": bytes.__name__,
                "hex": o.hex(' ', -1),
                "ascii": o.decode("ascii", errors="replace").replace('\ufffd', '.'),
                }
        if isinstance(o, MCFG_Item):
            r = o._header.copy()
            if self._partial:
                del r["data"]
        elif isinstance(o, MCFG_Trailer):
            r = {"reserved": o["reserved"], "data": o["data"]}
        elif isinstance(o, MCFG):
            r = o._header
        else:
            return super().default(o)
        r["__type__"] = type(o).__name__
        return r

def decode_hook(o):
    if o.get("__type__") not in [MCFG_Item.__name__, MCFG_Trailer.__name__, MCFG.__name__, bytes.__name__]:
        return o

    if o["__type__"] == bytes.__name__:
        return bytes.fromhex(o["hex"]) # TODO: error handling

    cls = getattr(mbntools.mcfg, o["__type__"])
    r = cls.__new__(cls)
    t = o["__type__"]
    del o["__type__"]
    if isinstance(r, MCFG_Item) or isinstance(r, MCFG_Trailer) or isinstance(r, MCFG):
        r._header = o
    else:
        raise Exception(f"Cannot decode unknown class: {t}")

    return r
