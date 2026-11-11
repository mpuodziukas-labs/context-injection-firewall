"""Regression: the mutation runner must not copy the target of a symlink into each scratch tree.
Before the fix, a symlinked model file was copied in full for every mutant and filled the disk."""
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import mutants


def test_fresh_keeps_symlinks_as_links(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 1024)
    os.symlink(str(big), str(root / "weights.bin"))
    mutants.ROOT = root
    dst = mutants.fresh(str(tmp_path / "scratch"), "m0")
    assert (dst / "weights.bin").is_symlink()
