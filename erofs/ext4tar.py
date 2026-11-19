#!/usr/bin/env python3
"""ext4tar.py <ext4 image> <offset bytes> <tar out or -> <listing out>

Reads an ext4 file system straight from an image file (no mount, no root) and
writes it as a POSIX (pax) tar stream: every directory, file, link, device
node and FIFO with its owner, group, mode, modification time (nanoseconds),
extended attributes (posix ACLs converted to the kernel's xattr form) and
hard links. mkfs.erofs --tar=f turns that stream into the EROFS image.

It also writes a listing of everything it read (one line per entry), which
verify.py compares with what comes back out of the finished EROFS image.

Only what andr36oid needs from a release image is supported: extents or
block maps, 32 or 64 bit group descriptors, in-inode and block xattrs.
Anything else (inline data, encryption, xattrs in inodes) stops the
conversion. Socket files, which tar cannot carry, are the one exception: they
are left out and listed as "s" lines, and verify.py reports them.
"""
import hashlib, os, stat, struct, sys, tarfile

PREFIX = {1: "user.", 2: "system.posix_acl_access", 3: "system.posix_acl_default",
          4: "trusted.", 6: "security.", 7: "system.", 8: "system.richacl"}


class Ext4:
    def __init__(self, path, offset):
        self.f = open(path, "rb")
        self.base = offset
        sb = self.read(1024, 1024)
        if struct.unpack_from("<H", sb, 56)[0] != 0xEF53:
            sys.exit("no ext4 superblock at offset %d" % offset)
        self.bs = 1024 << struct.unpack_from("<I", sb, 24)[0]
        self.ipg = struct.unpack_from("<I", sb, 40)[0]
        self.isize = struct.unpack_from("<H", sb, 88)[0]
        incompat = struct.unpack_from("<I", sb, 96)[0]
        if incompat & 0x8000:
            sys.exit("inline data is not supported")
        if incompat & 0x10000:
            sys.exit("encryption is not supported")
        if incompat & 0x400:
            sys.exit("xattrs stored in inodes (ea_inode) are not supported")
        self.desc = struct.unpack_from("<H", sb, 254)[0] if incompat & 0x80 else 32
        self.desc = self.desc or 32
        self.first = struct.unpack_from("<I", sb, 20)[0]
        self.gdt = (self.first + 1) * self.bs

    def read(self, pos, n):
        self.f.seek(self.base + pos)
        b = self.f.read(n)
        if len(b) != n:
            sys.exit("short read at %d" % pos)
        return b

    def inode(self, n):
        g, i = divmod(n - 1, self.ipg)
        d = self.read(self.gdt + g * self.desc, self.desc)
        table = struct.unpack_from("<I", d, 8)[0]
        if self.desc >= 64:
            table |= struct.unpack_from("<I", d, 40)[0] << 32
        return self.read(table * self.bs + i * self.isize, self.isize)

    # list of (logical block, physical block or None for unwritten, count)
    def extents(self, node):
        magic, entries, _, depth = struct.unpack_from("<HHHH", node, 0)
        if magic != 0xF30A:
            sys.exit("bad extent header")
        out = []
        for k in range(entries):
            e = node[12 + 12 * k: 24 + 12 * k]
            if depth == 0:
                lblk, length, hi, lo = struct.unpack("<IHHI", e)
                unwritten = length > 32768
                if unwritten:
                    length -= 32768
                out.append((lblk, None if unwritten else (hi << 32) | lo, length))
            else:
                _, lo, hi = struct.unpack_from("<IIH", e)
                out += self.extents(self.read(((hi << 32) | lo) * self.bs, self.bs))
        return out

    def blockmap(self, iblock, nblocks):
        ptrs = struct.unpack("<15I", iblock)
        per = self.bs // 4
        out = []
        def walk(block, level, start):
            if block == 0:
                return
            if level == 0:
                out.append((start, block, 1)); return
            sub = struct.unpack("<%dI" % per, self.read(block * self.bs, self.bs))
            span = per ** (level - 1)
            for k, b in enumerate(sub):
                if start + k * span >= nblocks:
                    break
                walk(b, level - 1, start + k * span)
        for k in range(12):
            walk(ptrs[k], 0, k)
        walk(ptrs[12], 1, 12)
        walk(ptrs[13], 2, 12 + per)
        walk(ptrs[14], 3, 12 + per + per * per)
        return out

    def chunks(self, raw, size):
        """Yield the file's bytes in order, holes as zeros."""
        flags = struct.unpack_from("<I", raw, 32)[0]
        nblocks = (size + self.bs - 1) // self.bs
        runs = self.extents(raw[40:100]) if flags & 0x80000 else self.blockmap(raw[40:100], nblocks)
        runs.sort()
        pos = 0
        for lblk, pblk, count in runs:
            start = lblk * self.bs
            if start >= size:
                break
            if start > pos:
                yield bytes(start - pos); pos = start
            length = min(count * self.bs, size - start)
            if pblk is None:
                yield bytes(length)
            else:
                done = 0
                while done < length:
                    n = min(length - done, 1 << 20)
                    yield self.read(pblk * self.bs + done, n); done += n
            pos = start + length
        if pos < size:
            yield bytes(size - pos)

    def data(self, raw, size):
        return b"".join(self.chunks(raw, size))


def acl(value):
    # ext4 keeps ACLs in a compact form; the kernel hands out the posix form.
    if struct.unpack_from("<I", value, 0)[0] != 1:
        sys.exit("unknown ext4 ACL version")
    out, p = [struct.pack("<I", 2)], 4
    while p < len(value):
        tag, perm = struct.unpack_from("<HH", value, p)
        if tag in (2, 8):
            ident = struct.unpack_from("<I", value, p + 4)[0]; p += 8
        else:
            ident = 0xFFFFFFFF; p += 4
        out.append(struct.pack("<HHI", tag, perm, ident))
    return b"".join(out)


def xattr_entries(buf, start, values_base, fs):
    out = {}
    p = start
    while p + 16 <= len(buf) and struct.unpack_from("<I", buf, p)[0] != 0:
        nlen, idx, voff, vinum, vsize = struct.unpack_from("<BBHII", buf, p)
        name = buf[p + 16: p + 16 + nlen].decode("utf-8", "surrogateescape")
        if vinum:
            sys.exit("xattr value in a separate inode is not supported")
        value = buf[values_base + voff: values_base + voff + vsize]
        if idx not in PREFIX:
            sys.exit("unknown xattr name index %d" % idx)
        full = PREFIX[idx] + name
        if idx in (2, 3):
            value = acl(value)
        out[full] = value
        p += (16 + nlen + 3) & ~3
    return out


def xattrs(fs, raw):
    out = {}
    if fs.isize > 128:
        extra = struct.unpack_from("<H", raw, 128)[0]
        p = 128 + extra
        if p + 4 <= len(raw) and struct.unpack_from("<I", raw, p)[0] == 0xEA020000:
            out.update(xattr_entries(raw, p + 4, p + 4, fs))
    acl_block = struct.unpack_from("<I", raw, 104)[0] | (struct.unpack_from("<H", raw, 118)[0] << 32)
    if acl_block:
        b = fs.read(acl_block * fs.bs, fs.bs)
        if struct.unpack_from("<I", b, 0)[0] != 0xEA020000:
            sys.exit("bad xattr block")
        out.update(xattr_entries(b, 32, 0, fs))
    return out


def meta(fs, raw):
    mode, uid_lo, size_lo = struct.unpack_from("<HHI", raw, 0)
    mtime = struct.unpack_from("<i", raw, 16)[0]
    gid_lo, links = struct.unpack_from("<HH", raw, 24)
    size_hi = struct.unpack_from("<I", raw, 108)[0]
    uid_hi, gid_hi = struct.unpack_from("<HH", raw, 120)
    nsec = 0
    if fs.isize > 128 and struct.unpack_from("<H", raw, 128)[0] >= 12:
        extra = struct.unpack_from("<I", raw, 136)[0]
        mtime += (extra & 3) << 32
        nsec = extra >> 2
    return dict(mode=mode, uid=uid_lo | uid_hi << 16, gid=gid_lo | gid_hi << 16,
                size=size_lo | size_hi << 32, mtime=mtime, nsec=nsec, links=links)


class Stream:
    def __init__(self, gen):
        self.gen, self.buf = gen, b""
    def read(self, n=-1):
        while n < 0 or len(self.buf) < n:
            try:
                self.buf += next(self.gen)
            except StopIteration:
                break
        if n < 0:
            n = len(self.buf)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def main():
    image, offset, tar_out, listing_out = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    fs = Ext4(image, offset)
    out = sys.stdout.buffer if tar_out == "-" else open(tar_out, "wb")
    tar = tarfile.open(fileobj=out, mode="w|", format=tarfile.PAX_FORMAT,
                       encoding="utf-8", errors="surrogateescape")
    listing = open(listing_out, "w", encoding="utf-8", errors="surrogateescape")
    seen = {}
    counts = dict(entries=0, files=0, bytes=0, xattrs=0, hardlinks=0, sockets=0)
    stack = [("", 2)]
    while stack:
        path, ino = stack.pop()
        raw = fs.inode(ino)
        m = meta(fs, raw)
        kind = stat.S_IFMT(m["mode"])
        name = path if path else "."
        info = tarfile.TarInfo(name)
        info.mode = m["mode"] & 0o7777
        info.uid, info.gid, info.uname, info.gname = m["uid"], m["gid"], "", ""
        info.mtime = m["mtime"]
        info.pax_headers = {"mtime": "%d.%09d" % (m["mtime"], m["nsec"])}
        xa = xattrs(fs, raw)
        for k, v in sorted(xa.items()):
            info.pax_headers["SCHILY.xattr." + k] = v.decode("utf-8", "surrogateescape")
        counts["xattrs"] += len(xa)
        xa_text = ",".join("%s=%s" % (k, hashlib.sha256(v).hexdigest()) for k, v in sorted(xa.items()))
        line = None
        if kind != stat.S_IFDIR and m["links"] > 1 and ino in seen:
            info.type, info.linkname = tarfile.LNKTYPE, seen[ino]
            tar.addfile(info)
            counts["hardlinks"] += 1
            line = "h %s -> %s" % (name, seen[ino])
        elif kind == stat.S_IFDIR:
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
            entries = []
            data = fs.data(raw, m["size"])
            p = 0
            while p + 8 <= len(data):
                child, rec, nlen, _ = struct.unpack_from("<IHBB", data, p)
                if rec < 8:
                    sys.exit("bad directory record in %s" % name)
                cname = data[p + 8: p + 8 + nlen].decode("utf-8", "surrogateescape")
                if child and cname not in (".", ".."):
                    entries.append((cname, child))
                p += rec
            for cname, child in sorted(entries, reverse=True):
                stack.append(((path + "/" if path else "") + cname, child))
            line = "d %s %o %d %d %d.%09d" % (name, info.mode, m["uid"], m["gid"], m["mtime"], m["nsec"])
        elif kind == stat.S_IFREG:
            info.type, info.size = tarfile.REGTYPE, m["size"]
            h = hashlib.sha256()
            def hashed():
                for c in fs.chunks(raw, m["size"]):
                    h.update(c); yield c
            tar.addfile(info, Stream(hashed()))
            counts["files"] += 1; counts["bytes"] += m["size"]
            line = "f %s %o %d %d %d %d.%09d %s" % (name, info.mode, m["uid"], m["gid"], m["size"], m["mtime"], m["nsec"], h.hexdigest())
        elif kind == stat.S_IFLNK:
            flags = struct.unpack_from("<I", raw, 32)[0]
            blocks = struct.unpack_from("<I", raw, 28)[0]
            if m["size"] < 60 and not flags & 0x80000 and blocks == 0:
                target = raw[40:40 + m["size"]]
            else:
                target = fs.data(raw, m["size"])
            info.type = tarfile.SYMTYPE
            info.linkname = target.decode("utf-8", "surrogateescape")
            tar.addfile(info)
            line = "l %s %d %d %d.%09d %s" % (name, m["uid"], m["gid"], m["mtime"], m["nsec"], info.linkname)
        elif kind in (stat.S_IFCHR, stat.S_IFBLK):
            b0, b1 = struct.unpack_from("<II", raw, 40)
            if b0:
                major, minor = (b0 >> 8) & 0xFF, b0 & 0xFF
            else:
                major, minor = (b1 & 0xFFF00) >> 8, (b1 & 0xFF) | ((b1 >> 12) & 0xFFF00)
            info.type = tarfile.CHRTYPE if kind == stat.S_IFCHR else tarfile.BLKTYPE
            info.devmajor, info.devminor = major, minor
            tar.addfile(info)
            line = "%s %s %o %d %d %d:%d" % ("c" if kind == stat.S_IFCHR else "b", name, info.mode, m["uid"], m["gid"], major, minor)
        elif kind == stat.S_IFIFO:
            info.type = tarfile.FIFOTYPE
            tar.addfile(info)
            line = "p %s %o %d %d" % (name, info.mode, m["uid"], m["gid"])
        elif kind == stat.S_IFSOCK:
            # A socket file is only a leftover name of a dead process; tar has
            # no type for it. It is left out and listed, never silently.
            counts["sockets"] += 1
            line = "s %s %o %d %d" % (name, info.mode, m["uid"], m["gid"])
        else:
            sys.exit("cannot represent %s (mode %o) in tar" % (name, m["mode"]))
        if kind != stat.S_IFDIR and m["links"] > 1 and ino not in seen:
            seen[ino] = name
        if xa_text and not line.startswith("h "):
            line += " xattr:" + xa_text
        listing.write(line + "\n")
        counts["entries"] += 1
    tar.close()
    if out is not sys.stdout.buffer:
        out.close()
    listing.close()
    print(" ".join("%s=%d" % kv for kv in counts.items()), file=sys.stderr)


if __name__ == "__main__":
    main()
