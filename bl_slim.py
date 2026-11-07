#!/usr/bin/env python3
import argparse
import base64
import ctypes
import ctypes.util
import errno
import hashlib
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

libc_name = ctypes.util.find_library("c") or "libc.so.6"
libc = ctypes.CDLL(libc_name, use_errno=True)

libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int64, ctypes.c_int64]
libc.fallocate.restype = ctypes.c_int

libc.lseek64.argtypes = [ctypes.c_int, ctypes.c_int64, ctypes.c_int]
libc.lseek64.restype = ctypes.c_int64

FALLOC_FL_KEEP_SIZE = 0x01
FALLOC_FL_PUNCH_HOLE = 0x02
SEEK_DATA = 3
SEEK_HOLE = 4

WWISE_LANGS = {
    "Chinese(Simplified)", "English(US)", "French(France)", "German",
    "Italian", "Japanese", "Korean", "Spanish(Spain)"
}

CHUNK_FILE_RE = re.compile(r"^pakchunk(\d+)-Windows_(\d+)_P\.(pak|ucas|utoc)$", re.IGNORECASE)


def fmt_size(n: int) -> str:
    if n >= (1 << 30) or n == 0:
        return f"{n / (1 << 30):8.2f} GB"
    return f"{n / (1 << 20):8.2f} MB"


def on_disk_bytes(directory: str) -> int:
    total = 0
    for root, _, files in os.walk(directory):
        for f in files:
            try:
                st = os.lstat(os.path.join(root, f))
                total += st.st_blocks * 512
            except OSError:
                pass
    return total


def zero_ranges(path: str, ranges: list[tuple[int, int]]):
    fd = os.open(path, os.O_RDWR)
    try:
        for start, end in ranges:
            length = end - start
            if length <= 0:
                continue
            res = libc.fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, start, length)
            if res != 0:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err), path)
    finally:
        os.close(fd)


def allocated_ranges(path: str) -> list[tuple[int, int]]:
    out = []
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        pos = 0
        while pos < size:
            data_start = libc.lseek64(fd, pos, SEEK_DATA)
            if data_start < 0:
                err = ctypes.get_errno()
                if err == errno.ENXIO:
                    break
                raise OSError(err, os.strerror(err), path)
            hole_start = libc.lseek64(fd, data_start, SEEK_HOLE)
            if hole_start < 0:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err), path)
            if hole_start > data_start:
                out.append((int(data_start), int(hole_start)))
            pos = int(hole_start)
    finally:
        os.close(fd)
    return out


def probe_unit(directory: str) -> int:
    probe_file = os.path.join(directory, "bl-slim-probe.tmp")
    n = 8 << 20
    try:
        with open(probe_file, "wb") as f:
            f.write(b"\x01" * n)
        zero_ranges(probe_file, [(1, n - 1)])
        a = allocated_ranges(probe_file)
        if len(a) == 2 and a[0][0] == 0 and a[1][1] == n and a[0][1] == n - a[1][0]:
            return a[0][1]
        return 0
    except OSError:
        return 0
    finally:
        if os.path.exists(probe_file):
            try:
                os.remove(probe_file)
            except OSError:
                pass


def u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def i32(b: bytes, off: int) -> int:
    return struct.unpack_from("<i", b, off)[0]


def i64(b: bytes, off: int) -> int:
    return struct.unpack_from("<q", b, off)[0]


def read_num(b: bytes, off: int, n: int, big_endian: bool) -> int:
    v = 0
    for i in range(n):
        idx = off + (i if big_endian else n - 1 - i)
        v = (v << 8) | b[idx]
    return v


def read_fstring(b: bytes, p: int) -> tuple[str, int]:
    n = i32(b, p)
    p += 4
    length = -n * 2 if n < 0 else n
    raw = b[p : p + length]
    p += length
    if n < 0:
        s = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    else:
        s = raw.decode("latin-1").rstrip("\x00")
    return s, p


class Toc:
    def __init__(self, block_sz, ids, header, span_off, span_len, block_off, block_size):
        self.block_sz = block_sz
        self.ids = ids
        self.header = header
        self.span_off = span_off
        self.span_len = span_len
        self.block_off = block_off
        self.block_size = block_size


class Pak:
    def __init__(self, mount: str, data_end: int):
        self.mount = mount
        self.data_end = data_end
        self.entries: dict[str, int] = {}
        self.ends = None


def bad(path: str, msg: str) -> ValueError:
    return ValueError(f"{os.path.basename(path)}: {msg}")


def read_toc(path: str) -> Toc:
    with open(path, "rb") as f:
        d = f.read()
    if len(d) < 104 or d[:16] != b"-==--==--==--==-" or d[16] != 8 or u32(d, 32) != 12:
        raise bad(path, "not a version 8 IoStore TOC")
    if (d[80] & 6) != 0 or u32(d, 52) != 1:
        raise bad(path, "encrypted, signed or split containers are not supported")
    n = u32(d, 24)
    nb = u32(d, 28)
    p = u32(d, 20)
    s = p + n * 12
    b = s + n * 10 + u32(d, 84) * 4 + u32(d, 96) * 4
    block_sz = u32(d, 44)

    ids = [base64.b64encode(d[p + i * 12 : p + (i + 1) * 12]).decode("ascii") for i in range(n)]
    header = [d[p + i * 12 + 11] == 6 for i in range(n)]
    span_off = [read_num(d, s + i * 10, 5, True) for i in range(n)]
    span_len = [read_num(d, s + i * 10 + 5, 5, True) for i in range(n)]
    block_off = [read_num(d, b + i * 12, 5, False) for i in range(nb)]
    block_size = [read_num(d, b + i * 12 + 5, 3, False) for i in range(nb)]

    expected_rem = n * 24
    actual_rem = len(d) - (b + nb * 12 + u32(d, 36) * u32(d, 40) + u32(d, 48))
    if actual_rem != expected_rem:
        raise bad(path, "TOC sections do not add up to the file size")
    return Toc(block_sz, ids, header, span_off, span_len, block_off, block_size)


def read_pak11(path: str) -> Pak | None:
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size < 221:
            raise bad(path, "too small to be a pak")
        f.seek(size - 221)
        ft = f.read(221)
        if u32(ft, 17) != 0x5A6F12E1:
            raise bad(path, "no pak footer")
        ver = i32(ft, 21)
        if ver != 11:
            raise bad(path, f"pak version {ver}, expected 11")
        if ft[16] != 0:
            return None
        io = i64(ft, 25)
        idx_len = i64(ft, 33)
        f.seek(io)
        idx = f.read(idx_len)
        if len(idx) != idx_len:
            raise bad(path, "file ends early")

        p = 0
        mount, p = read_fstring(idx, p)
        pak = Pak(mount, min(io, size - 221))
        if u32(idx, p + 12) != 0:
            pak.data_end = min(pak.data_end, i64(idx, p + 16))
            p += 36
        if u32(idx, p + 16) == 0:
            return None
        dir_off = i64(idx, p + 20)
        dir_size = i64(idx, p + 28)
        pak.data_end = min(pak.data_end, dir_off)
        enc = p + 60
        q = enc + i32(idx, p + 56) + 4
        plain = []
        n_plain = u32(idx, q - 4)
        for _ in range(n_plain):
            plain.append(i64(idx, q))
            q += (57 + 16 * u32(idx, q + 48)) if u32(idx, q + 24) != 0 else 53
        if q != len(idx):
            raise bad(path, "index layout does not add up to its size")

        f.seek(dir_off)
        dirs = f.read(dir_size)
        if len(dirs) != dir_size:
            raise bad(path, "file ends early")
        r = 0
        folders = i32(dirs, r)
        r += 4
        for _ in range(folders):
            folder, r = read_fstring(dirs, r)
            files_count = i32(dirs, r)
            r += 4
            for _ in range(files_count):
                fname, r = read_fstring(dirs, r)
                loc = i32(dirs, r)
                r += 4
                if loc == -2147483648:
                    continue
                fl = 0 if loc < 0 else u32(idx, enc + loc)
                at = enc + loc + (8 if (fl & 0x3F) == 0x3F else 4)
                if loc < 0:
                    val = plain[-loc - 1]
                elif (fl >> 31) != 0:
                    val = u32(idx, at)
                else:
                    val = i64(idx, at)
                pak.entries[folder + fname] = val
        return pak


def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out = []
    for s, e in sorted(ranges):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def upper_bound(arr: list[int], val: int) -> int:
    lo, hi = 0, len(arr)
    while lo < hi:
        mid = (lo + hi) // 2
        if arr[mid] <= val:
            lo = mid + 1
        else:
            hi = mid
    return lo


def up_to_next(starts: list[int], lo: int, end: int) -> tuple[int, int]:
    k = upper_bound(starts, lo)
    return (lo, starts[k] if k < len(starts) else end)


def overlap(held: list[tuple[int, int]], starts: list[int], lo: int, hi: int) -> int:
    t = 0
    j = max(0, upper_bound(starts, lo) - 1)
    while j < len(held) and held[j][0] < hi:
        t += max(0, min(hi, held[j][1]) - max(lo, held[j][0]))
        j += 1
    return t


def hash_ranges(path: str, ranges: list[tuple[int, int]]) -> str:
    sha = hashlib.sha1()
    buf_size = 16 << 20
    with open(path, "rb") as f:
        for start, end in ranges:
            f.seek(start)
            rem = end - start
            while rem > 0:
                chunk = f.read(min(rem, buf_size))
                if not chunk:
                    raise bad(path, f"file ends before byte {end}")
                sha.update(chunk)
                rem -= len(chunk)
    return base64.b64encode(sha.digest()).decode("ascii")


class Slim:
    def __init__(self, paks_dir: str):
        self.paks = paks_dir
        self.unit = 0
        self.saves = 0
        self.foreign: list[str] = []
        self.skipped: list[str] = []
        self.voices: dict[int, str] = {}
        self.drop: dict[str, int] = {}
        self.old: dict[str, list[tuple[int, int]]] = {}
        self.todo: dict[str, list[tuple[int, int]]] = {}
        self.patch: dict[str, int] = {}
        self.chunk_of: dict[str, int] = {}
        self.chunks: dict[int, list[str]] = {}
        self.pak_cache: dict[str, Pak | None] = {}

        self.disk_paths: dict[str, str] = {}
        found = []
        for entry in os.listdir(paks_dir):
            full = os.path.join(paks_dir, entry)
            if not os.path.isfile(full):
                continue
            self.disk_paths[full.lower()] = full
            m = CHUNK_FILE_RE.match(entry)
            if m:
                found.append((full, int(m.group(1)), int(m.group(2))))

        bad_files = set()
        for f, _, _ in found:
            try:
                if f.lower().endswith(".utoc"):
                    read_toc(f)
                elif f.lower().endswith(".pak"):
                    self.read_pak(f)
            except Exception as e:
                if isinstance(e, (OSError, PermissionError)):
                    raise
                bad_files.add(f.lower())
                if f.lower().endswith(".utoc"):
                    bad_files.add((os.path.splitext(f)[0] + ".ucas").lower())

        self.skipped = sorted(os.path.basename(f) for f, _, _ in found if f.lower() in bad_files)
        found = [(f, c, p) for f, c, p in found if f.lower() not in bad_files]

        for f, c, p in found:
            self.patch[f] = p
            self.chunk_of[f] = c
            self.chunks.setdefault(c, []).append(f)

        for c, files in sorted(self.chunks.items()):
            lang = self.chunk_language(files)
            if lang:
                self.voices[c] = lang

    def ucas_for_utoc(self, utoc_path: str) -> str:
        cand = (os.path.splitext(utoc_path)[0] + ".ucas").lower()
        return self.disk_paths.get(cand, os.path.splitext(utoc_path)[0] + ".ucas")

    def read_pak(self, path: str) -> Pak | None:
        if path not in self.pak_cache:
            self.pak_cache[path] = read_pak11(path)
        return self.pak_cache[path]

    def chunk_language(self, files: list[str]) -> str | None:
        langs = set()
        for f in files:
            if f.lower().endswith(".pak"):
                pak = self.read_pak(f)
                if pak is None:
                    return None
                if pak.entries and not pak.mount.rstrip("/").endswith("WwiseAudio"):
                    return None
                for k in pak.entries:
                    parts = k.strip("/").split("/")
                    if parts and parts[0] == "Media":
                        parts = parts[1:]
                    langs.add(parts[0] if len(parts) > 1 else None)
            elif f.lower().endswith(".utoc"):
                if any(not h for h in read_toc(f).header):
                    return None
        if len(langs) == 1:
            lang = next(iter(langs))
            if lang in WWISE_LANGS:
                return lang
        return None

    def check(self, f: str, raw: list[tuple[int, int]], used: list[tuple[int, int]]):
        old = merge_ranges(raw)
        if not old:
            return
        os_starts = [r[0] for r in old]
        for u0, u1 in used:
            if overlap(old, os_starts, u0, u1) > 0:
                raise bad(f, f"an old range covers data the game reads at {u0}")
        if old[-1][1] > os.path.getsize(f):
            raise bad(f, "an old range runs past the end of the file")
        self.old[f] = old

    def plan_iostore(self, skip_lower: set[str]):
        tocs: dict[str, Toc] = {}
        newest: dict[str, int] = {}
        for f, p_num in self.patch.items():
            ucas = self.ucas_for_utoc(f)
            if f.lower().endswith(".utoc") and f.lower() not in skip_lower and ucas.lower() not in skip_lower:
                t = read_toc(f)
                tocs[f] = t
                for cid in t.ids:
                    newest[cid] = max(newest.get(cid, 0), p_num)

        for f, t in tocs.items():
            used = set()
            covered = set()
            p_num = self.patch[f]
            for i in range(len(t.ids)):
                if t.span_len[i] <= 0:
                    continue
                keep = t.header[i] or newest[t.ids[i]] <= p_num
                b_start = t.span_off[i] // t.block_sz
                b_end = (t.span_off[i] + t.span_len[i] - 1) // t.block_sz
                for b in range(b_start, b_end + 1):
                    covered.add(b)
                    if keep:
                        used.add(b)
            starts = sorted(t.block_off)
            raw = [up_to_next(starts, t.block_off[b], t.block_off[b] + t.block_size[b]) for b in (covered - used)]
            used_ranges = merge_ranges([(t.block_off[b], t.block_off[b] + t.block_size[b]) for b in used])
            self.check(self.ucas_for_utoc(f), raw, used_ranges)

    def plan_pak(self, skip_lower: set[str]):
        paks: dict[str, Pak] = {}
        newest: dict[str, int] = {}
        for f, p_num in self.patch.items():
            if f.lower().endswith(".pak") and f.lower() not in skip_lower:
                p = self.read_pak(f)
                if p is not None:
                    paks[f] = p
                    for e in p.entries:
                        k = (p.mount + e).lower()
                        newest[k] = max(newest.get(k, 0), p_num)

        for f, p in paks.items():
            p_num = self.patch[f]
            used = {off for e, off in p.entries.items() if newest[(p.mount + e).lower()] <= p_num}
            starts = sorted(set(p.entries.values()))
            raw = [up_to_next(starts, s, p.data_end) for s in starts if s not in used]
            used_ranges = [(s, s + 1) for s in sorted(used)]
            self.check(f, raw, used_ranges)

    def prepare(self, keep: list[str]):
        keep_set = set(keep)
        installed_langs = set(self.voices.values())
        for k in keep:
            if self.voices and k not in installed_langs:
                raise RuntimeError(f"No {k} voice pack is installed. Found: {', '.join(sorted(installed_langs))}")

        for c, lang in self.voices.items():
            if lang not in keep_set:
                for f in sorted(self.chunks[c], key=lambda x: (x.lower().endswith(".pak"), x)):
                    self.foreign.append(f)
                    self.drop[lang] = self.drop.get(lang, 0) + os.path.getsize(f)

        skip_lower = {f.lower() for f in self.foreign}
        self.plan_iostore(skip_lower)
        self.plan_pak(skip_lower)

        self.unit = probe_unit(self.paks)
        if self.unit == 0:
            return

        for f, ranges in list(self.old.items()):
            held = allocated_ranges(f)
            hs = [h[0] for h in held]
            todo_ranges = []
            aligned_old = []
            for r0, r1 in ranges:
                a0 = ((r0 + self.unit - 1) // self.unit) * self.unit
                a1 = (r1 // self.unit) * self.unit
                if a0 < a1:
                    aligned_old.append((a0, a1))
                    gain = overlap(held, hs, a0, a1)
                    if gain > 0:
                        self.saves += gain
                        todo_ranges.append((a0, a1))
            self.old[f] = aligned_old
            if todo_ranges:
                self.todo[f] = todo_ranges

    def apply(self):
        for f in self.foreign:
            os.remove(f)
        for idx, (f, ranges) in enumerate(self.todo.items(), 1):
            print(f"  [{idx}/{len(self.todo)}] {os.path.basename(f)}")
            o = self.old[f]
            size = os.path.getsize(f)
            kept = []
            for j in range(len(o) + 1):
                r0 = o[j - 1][1] if j > 0 else 0
                r1 = o[j][0] if j < len(o) else size
                if r0 < r1:
                    kept.append((r0, r1))
            before_hash = hash_ranges(f, kept)
            try:
                zero_ranges(f, ranges)
            finally:
                if hash_ranges(f, kept) != before_hash:
                    raise bad(f, "data the game reads changed. Run Verify integrity in Steam.")


def find_game(app_id: int) -> str | None:
    home = str(Path.home())
    candidates = [
        os.path.join(home, ".local/share/Steam"),
        os.path.join(home, ".steam/steam"),
        os.path.join(home, ".var/app/com.valvesoftware.Steam/.local/share/Steam"),
    ]
    libs = [c for c in candidates if os.path.isdir(c)]
    for base in list(libs):
        vdf = os.path.join(base, "steamapps/libraryfolders.vdf")
        if os.path.isfile(vdf):
            with open(vdf, "r", encoding="utf-8", errors="ignore") as f:
                for m in re.finditer(r'"path"\s+"(.+?)"', f.read()):
                    libs.append(m.group(1).replace("\\\\", "/"))

    seen = set()
    for lib in libs:
        if lib in seen:
            continue
        seen.add(lib)
        acf = os.path.join(lib, f"steamapps/appmanifest_{app_id}.acf")
        if os.path.isfile(acf):
            with open(acf, "r", encoding="utf-8", errors="ignore") as f:
                m = re.search(r'"installdir"\s+"(.+?)"', f.read())
                if m:
                    cand = os.path.join(lib, "steamapps/common", m.group(1))
                    if os.path.isdir(cand):
                        return cand
    return None


def is_game_running() -> bool:
    res = subprocess.run(["pgrep", "-f", "Borderlands4.exe"], capture_output=True)
    return res.returncode == 0


def main():
    parser = argparse.ArgumentParser(description="Shrinks a Borderlands 4 install on Linux.")
    parser.add_argument("-Scan", "--scan", action="store_true", help="Dry run scan only")
    parser.add_argument("-Keep", "--keep", type=str, default="", help="Comma-separated languages to keep")
    parser.add_argument("-GameDir", "--gamedir", type=str, default="", help="Path to Borderlands 4 folder")
    parser.add_argument("-Yes", "--yes", action="store_true", help="Skip confirmation prompt")
    args = parser.parse_args()

    game_dir = args.gamedir.strip().strip('"').strip("'")
    if not game_dir:
        game_dir = find_game(1285190) or ""
    if not game_dir:
        game_dir = input("Paste your Borderlands 4 folder path: ").strip().strip('"').strip("'")

    paks_dir = os.path.join(game_dir, "OakGame", "Content", "Paks")
    if not os.path.isdir(paks_dir):
        print(f"No Borderlands found at {game_dir} (missing OakGame/Content/Paks)")
        sys.exit(2)

    print(f"Borderlands 4: {game_dir}")

    if not args.scan:
        if is_game_running():
            print("Borderlands 4 is running. Close it first.")
            sys.exit(1)
        sa = os.path.dirname(os.path.dirname(game_dir.rstrip("/")))
        acf = os.path.join(sa, "appmanifest_1285190.acf")
        if os.path.isfile(acf):
            with open(acf, "r", encoding="utf-8", errors="ignore") as f:
                if not re.search(r'"StateFlags"\s+"4"', f.read()):
                    print("Steam is updating or checking the game. Let it finish first.")
                    sys.exit(1)

    s = Slim(paks_dir)
    langs = sorted(set(s.voices.values()))
    lang_map = {l.lower(): l for l in langs}
    keep = [x.strip() for x in args.keep.split(",") if x.strip()]

    if not keep and len(langs) > 1:
        print("Voice languages installed:")
        for idx, l in enumerate(langs, 1):
            print(f"  {idx}. {l}")
        ans = input("Numbers of the ones to keep, like 1,3 (English(US) is always kept, Enter = only English): ").strip()
        if ans:
            for part in re.split(r"[,\s]+", ans):
                if part.isdigit() and 1 <= int(part) <= len(langs):
                    keep.append(langs[int(part) - 1])
                elif part:
                    keep.append(part)
        else:
            keep = ["English(US)"]

    if not keep:
        keep = [langs[0]] if len(langs) == 1 else ["English(US)"]
 
    normalized_keep = []
    for k in keep:
        canonical = lang_map.get(k.lower(), k)
        if canonical not in normalized_keep:
            normalized_keep.append(canonical)
    keep = normalized_keep

    if "English(US)" in langs and "English(US)" not in keep:
        keep = ["English(US)"] + keep
        print("Keeping English(US) too. The game seems to need the English voice files even if you play in another language.")
    elif langs and "English(US)" not in langs:
        print('The English(US) voice files are missing and the game seems to need them. Run "Verify integrity of game files" in Steam, then run this again.')
        keep = [k for k in keep if k in langs] or list(langs)

    print("Reading the game files...")
    s.prepare(keep)
    before = on_disk_bytes(game_dir)

    if s.skipped:
        print(f"Ignoring {len(s.skipped)} file(s) this tool does not understand: {', '.join(s.skipped)}")

    print(f"\nGame on disk now:        {fmt_size(before)}")
    for k, v in sorted(s.drop.items()):
        print(f"  {k:<21} {fmt_size(v)}")
    print(f"Voice languages to drop: {fmt_size(sum(s.drop.values()))}   (keeping {', '.join(keep)})")
    print(f"Old patch copies:        {fmt_size(s.saves)}   in {len(s.todo)} files")

    if s.unit == 0:
        print("Old patch copies stay: this filesystem cannot punch sparse holes in files.")

    if not s.foreign and not s.todo:
        print("Nothing to do.")
        return
    if args.scan:
        return

    if not args.yes:
        ans = input("Go ahead? (y/n) ").strip().lower()
        if not ans.startswith("y"):
            print("Nothing changed.")
            sys.exit(1)

    s.apply()
    after = on_disk_bytes(game_dir)
    print(f"\nBefore:  {fmt_size(before)}")
    print(f"After:   {fmt_size(after)}")
    print(f"Saved:   {fmt_size(before - after)}")
    if s.todo:
        print('Note: Standard file browsers show apparent size. Use "du -sh" on your BL4 folder to see the actual folder size.')


if __name__ == "__main__":
    main()
