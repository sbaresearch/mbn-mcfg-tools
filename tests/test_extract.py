import filecmp

import pytest

from mbn_mcfg_tools.mbn import Mbn

from .mbns import mbn_paths

@pytest.mark.parametrize("fp", mbn_paths())
def test_extract_roundtrip(tmp_path, fp):
    exdir = tmp_path / "exdir"
    tmpf = tmp_path / "test.mbn"

    with open(fp, "rb") as f:
        mbn = Mbn(f)
        mbn.extract(exdir)

    try:
        mbn = Mbn.pack(exdir, tmpf)
        mbn.write()
    finally:
        mbn.close()

    assert filecmp.cmp(fp, tmpf, shallow=False)
