import filecmp
import shutil

import pytest

from mbn_mcfg_tools.mbn import Mbn

from .mbns import mbn_paths

@pytest.mark.parametrize("fp", mbn_paths())
def test_check_hashes(fp):
    with open(fp, "rb") as f:
        mbn = Mbn(f)
        assert mbn.check_hashes()

@pytest.mark.parametrize("fp", mbn_paths())
def test_rewrite_hashes_roundtrip(tmp_path, fp):
    tmpf = tmp_path / "test.mbn"
    shutil.copyfile(fp, tmpf)

    with open(tmpf, "r+b") as f:
        mbn = Mbn(f)
        mbn.rewrite_hashes()

    assert filecmp.cmp(fp, tmpf, shallow=False)
