#!/usr/bin/env python3

import argparse
import functools
import os
import shutil
import sys

import colorama

from mbn_mcfg_tools.mbn import Mbn

class DiffWriter:
    def __init__(self, stream, maxwidth=128, use_color=True):
        self._stream = stream
        self._col, self._lin = shutil.get_terminal_size((80, 20))
        self._col = min(maxwidth, self._col)
        self._pos = 0
        self._addr = 0
        self._use_color = use_color

    def close(self):
        self._stream.close()

    def _fmt_addr(self) -> str:
        return f"0x{self._addr:08x}: "

    def write(self, *args):
        while max(*map(len, args)) > 0:
            nbytes = (self._col - (len(self._fmt_addr()) + 1) - self._pos) // 3

            if nbytes <= 0:
                self._pos = 0
                continue

            self._write(*tuple(map(lambda x: x[:nbytes], args)))
            self._stream.write('\n')
            args = tuple(map(lambda x: x[nbytes:], args))

    def _write(self, *args):
        addr = self._fmt_addr()
        lines = [[' ' * len(addr)] for _ in range(len(args) - 1)]
        lines.append([addr])

        for x in zip_longest(*args):
            for i, y in enumerate(x[-1:0:-1]):
                if y is None:
                    if x[0] is not None and self._use_color:
                        t = f"{colorama.Back.RED}  {colorama.Back.RESET}"
                    else:
                        t = "  "
                elif x[0] is None:
                    if self._use_color:
                        t = f"{colorama.Fore.GREEN}{y:02x}{colorama.Fore.RESET}"
                    else:
                        t = f"{y:02x}"
                elif y == x[0]:
                    t = "  "
                else:
                    if self._use_color:
                        t = f"{colorama.Fore.YELLOW}{y:02x}{colorama.Fore.RESET}"
                    else:
                        t = f"{y:02x}"
                lines[i].append(t)

            if x[0] is not None:
                t = f"{x[0]:02x}"
            else:
                t = "  "
            lines[-1].append(t)

        for l in lines:
            l.append('\n')
            self._stream.write(' '.join(l))

        m = max(*map(len, args))
        self._pos += m * 3
        self._addr += m

def zip_longest(*args):
    args = tuple(map(iter, args))

    while True:
        r = tuple(map(lambda i: next(i, None), args))

        if all(map(lambda x: x is None, r)):
            return

        yield r

def _stdout_istty():
    return os.isatty(sys.stdout.fileno())

@functools.cache
def use_color() -> bool:
    return ARGS.color != "never" and _stdout_istty() or ARGS.color == "always"

def parse_args():
    parser = argparse.ArgumentParser(prog="mbndiff", description="Compare contents of MBN files.")
    parser.add_argument("file1", metavar="file")
    parser.add_argument("file2", metavar="file")
    parser.add_argument("--color", "-c", choices=["always", "never"])
    parser.add_argument("--quiet", "-q", action="store_true")
    return parser.parse_args()

def parse_mbns(mbn1_path: str, mbn2_path: str) -> tuple[Mbn, Mbn]:
    with open(mbn1_path, "rb") as f, open(mbn2_path, "rb") as g:
        mbn1 = Mbn(f)
        mbn2 = Mbn(g)
    return mbn1, mbn2

def compare_types(n1, n2, i1, i2):
    items = i1 + i2
    if all(map(lambda x: x["type"] == items[0]["type"], items[1:])):
        return

    print(f"Types differ:")
    print(f"{n1}:")
    for t in i1:
        print(f"  0b{t['type']:08b}")
    print(f"{n2}:")
    for t in i2:
        print(f"  0b{t['type']:08b}")

def compare_attributes(n1, n2, i1, i2):
    items = i1 + i2
    if all(map(lambda x: x["attributes"] == items[0]["attributes"], items[1:])):
        return

    print(f"Attributes differ:")
    print(f"{n1}:")
    for a in i1:
        print(f"  0b{a['attributes']:08b}")
    print(f"{n2}:")
    for a in i2:
        print(f"  0b{a['attributes']:08b}")

def compare_files(n1, n2, i1, i2):
    compare_types(n1, n2, i1, i2)
    compare_attributes(n1, n2, i1, i2)
    items = i1 + i2
    if all(map(lambda x: x["data"] == items[0]["data"], items[1:])):
        print("Content is identical.")
        return

    print(f"Content differs:")
    for _ in i2:
        print(f"  {n2}")
    for _ in i1:
        print(f"  {n1}")

    d = DiffWriter(sys.stdout, use_color=use_color())
    d.write(*map(lambda x: x["data"], items))

def compare_nv_items(n1, n2, i1, i2):
    compare_types(n1, n2, i1, i2)
    compare_attributes(n1, n2, i1, i2)
    items = i1 + i2
    if all(map(lambda x: x["data"] == items[0]["data"], items[1:])):
        print("Content is identical.")
        return

    print(f"NV content differs:")
    for _ in i2:
        print(f"  {n2}")
    for _ in i1:
        print(f"  {n1}")

    d = DiffWriter(sys.stdout, use_color=use_color())
    d.write(*map(lambda x: x["data"], items))

def test():
    d = DiffWriter(sys.stdout)
    d.write(b'\x07\x01', b"", b"\x07\x01\x05")

def show_fname(fname: bytes) -> str:
    return fname.strip(b'\x00').decode(errors="replace")

def main():
    mbn1, mbn2 = parse_mbns(ARGS.file1, ARGS.file2)
    mcfg1 = mbn1["mcfg"]
    mcfg2 = mbn2["mcfg"]
    common_files = set(mcfg1.filenames()) & set(mcfg2.filenames())
    common_nv_items = set(mbn1["mcfg"].nv_ids()) & set(mbn2["mcfg"].nv_ids())

    # TODO
    print(f"File items only in '{ARGS.file1}':")
    for f in sorted(set(mcfg1.filenames()) - common_files):
        print(f"  {show_fname(f)}")

    print(f"File items only in '{ARGS.file2}':")
    for f in sorted(set(mcfg2.filenames()) - common_files):
        print(f"  {show_fname(f)}")

    print(f"NV items only in '{ARGS.file1}':")
    for f in sorted(set(mcfg1.nv_ids()) - common_nv_items):
        print(f"  {f}")

    print(f"NV items only in '{ARGS.file2}':")
    for f in sorted(set(mcfg2.nv_ids()) - common_nv_items):
        print(f"  {f}")

    for f in common_files:
        fi1 = mcfg1.get_file_items(f)
        fi2 = mcfg2.get_file_items(f)

        assert len(fi1) > 0 and len(fi2) > 0

        fname = f.strip(b'\x00').decode(errors="replace")
        if ARGS.quiet:
            print(f"File {fname} differs.")
        else:
            print(f"=== {fname} ===")
            compare_files(ARGS.file1, ARGS.file2, fi1, fi2)

    for nvid in common_nv_items:
        nv1 = mcfg1.get_nv_items(nvid)
        nv2 = mcfg2.get_nv_items(nvid)

        assert len(nv1) > 0 and len(nv2) > 0

        if ARGS.quiet:
            print(f"NV item {nvid} differs.")
        else:
            print(f"=== NV id {nvid} ===")
            compare_nv_items(ARGS.file1, ARGS.file2, nv1, nv2)

if __name__ == "__main__":
    ARGS = parse_args()
    colorama.just_fix_windows_console()
    main()
    #test()
