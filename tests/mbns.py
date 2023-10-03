import functools
import os

import pytest

from pathlib import Path

TESTMBNSDIR = Path("testmbns")

@functools.cache
def mbn_paths():
    xfail = []

    def f(p):
        r = TESTMBNSDIR / p
        if p in xfail:
            return pytest.param(r, marks=pytest.mark.xfail(reason="Possibly invalid MBN file. (needs further investigation)"))
        else:
            return r

    return list(map(f, os.listdir(TESTMBNSDIR)))
