#!/usr/bin/env python3
"""verify.py <source listing> <extracted tree> [<erofs image> <dump.erofs>]

Walks a tree extracted from the finished EROFS image (fsck.erofs --extract,
run under fakeroot when not root so owners survive) in the same order as
ext4tar.py read the source, writes the same kind of listing and compares the
two line by line: kind, path, mode, owner, group, size, modification time in
nanoseconds, link target, device numbers, hard links and the sha256 of every
file's contents.

Extended attributes are compared separately: when an image and dump.erofs are
given, every path that carries xattrs in the source is looked up in the image
and its names and values must match exactly; a tree walk alone cannot see
them when fsck.erofs does not restore xattrs.
"""
import hashlib, os, stat, subprocess, sys


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def walk(root):
    seen = {}
    stack = [""]
    while stack:
        rel = stack.pop()
        full = os.path.join(root, rel) if rel else root
        st = os.lstat(full)
        name = rel if rel else "."
        kind = stat.S_IFMT(st.st_mode)
        perm = st.st_mode & 0o7777
        mt = "%d.%09d" % (st.st_mtime_ns // 10**9, st.st_mtime_ns % 10**9)
        key = (st.st_dev, st.st_ino)
        if kind != stat.S_IFDIR and st.st_nlink > 1 and key in seen:
            yield "h %s -> %s" % (name, seen[key]); continue
        if kind != stat.S_IFDIR and st.st_nlink > 1:
            seen[key] = name
        if kind == stat.S_IFDIR:
            names = sorted(os.listdir(full), key=lambda s: s.encode("utf-8", "surrogateescape"))
            for n in reversed(names):
                stack.append((rel + "/" if rel else "") + n)
            yield "d %s %o %d %d %s" % (name, perm, st.st_uid, st.st_gid, mt)
        elif kind == stat.S_IFREG:
            yield "f %s %o %d %d %d %s %s" % (name, perm, st.st_uid, st.st_gid, st.st_size, mt, sha(full))
        elif kind == stat.S_IFLNK:
            yield "l %s %d %d %s %s" % (name, st.st_uid, st.st_gid, mt, os.readlink(full))
        elif kind in (stat.S_IFCHR, stat.S_IFBLK):
            yield "%s %s %o %d %d %d:%d" % ("c" if kind == stat.S_IFCHR else "b", name, perm, st.st_uid, st.st_gid,
                                            os.major(st.st_rdev), os.minor(st.st_rdev))
        elif kind == stat.S_IFIFO:
            yield "p %s %o %d %d" % (name, perm, st.st_uid, st.st_gid)
        else:
            yield "? %s" % name


def main():
    src_listing, tree = sys.argv[1], sys.argv[2]
    image = sys.argv[3] if len(sys.argv) > 3 else None
    dump = sys.argv[4] if len(sys.argv) > 4 else "dump.erofs"
    expected, wanted_xattrs, sockets = [], {}, []
    with open(src_listing, encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            line = line.rstrip("\n")
            base, sep, xa = line.partition(" xattr:")
            if base.startswith("s "):
                sockets.append(base); continue
            expected.append(base)
            if sep:
                wanted_xattrs[base.split(" ", 2)[1]] = dict(kv.split("=", 1) for kv in xa.split(","))
    bad = 0
    got = walk(tree)
    for n, want in enumerate(expected):
        have = next(got, None)
        if have != want:
            print("differs at entry %d:\n  source: %s\n  erofs:  %s" % (n + 1, want, have), file=sys.stderr)
            bad += 1
            if bad > 20:
                break
    extra = next(got, None)
    if extra is not None and not bad:
        print("erofs has more entries, first: %s" % extra, file=sys.stderr); bad += 1
    if bad:
        sys.exit("listing differs")
    for line in sockets:
        print("left out (tar cannot carry a socket file): %s" % line)
    print("verified: %d entries (kind, mode, owner, group, size, mtime ns, link target, devices, hard links, contents)" % len(expected))
    if image is None:
        print("xattrs: not checked (no image given); source has xattrs on %d paths" % len(wanted_xattrs))
        return
    for path, want in sorted(wanted_xattrs.items()):
        p = "/" if path == "." else "/" + path
        out = subprocess.run([dump, "-x", "--path=" + p, image], capture_output=True).stdout
        have = parse_dump(out)
        if have != want:
            sys.exit("xattrs differ on %s: source %s, erofs %s" % (p, want, have))
    print("verified: xattrs on %d paths (names and sha256 of values)" % len(wanted_xattrs))


def parse_dump(out):
    # dump.erofs -x prints one "name = value" (or quoted) line per xattr; the
    # value text is hashed as bytes after unescaping where possible.
    have = {}
    for raw in out.split(b"\n"):
        line = raw.strip()
        if b"=" not in line or line.startswith(b"Path") or line.startswith(b"NID"):
            continue
        name, _, value = line.partition(b"=")
        name = name.strip().decode("utf-8", "surrogateescape")
        if "." not in name or " " in name:
            continue
        have[name] = hashlib.sha256(value.strip()).hexdigest()
    return have


if __name__ == "__main__":
    main()
