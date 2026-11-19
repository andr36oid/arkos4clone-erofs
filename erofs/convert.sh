#!/bin/bash
# convert.sh <disk image> <output folder> <version> <revision>
#
# Takes the root filesystem out of an ArkOS-family release image and writes it again
# as a compressed read-only EROFS image, packed with xz (and cut into parts only
# if it is still too large for one GitHub release file), with a manifest.json
# that describes it. Nothing in the filesystem is changed or added (only the
# rootless mode leaves socket files out, see below): after writing, every
# file, link, owner, mode and extended attribute is
# compared with the original.
#
# ArkOS and ArkOS4Clone keep the root filesystem on ext4, dArkOS and
# dArkOS4Clone on btrfs; both work.
#
# Two ways to read the source, same result:
#  - as root (the GitHub workflow): loop-mount the partition read-only, build
#    from the mounted tree, mount the EROFS image and compare the two trees.
#  - without root (A36_ROOTLESS=1, or automatically when not root): ext4 only.
#    ext4tar.py reads the file system straight from the image file and streams
#    it as a pax tar (owners, modes, nanosecond times, xattrs, hard links) into
#    mkfs.erofs --tar=f. verify.py then compares the source listing with a tree
#    extracted from the EROFS image under fakeroot (so owners survive).
#    Socket files cannot travel through tar; they are left out and listed.
#
# IMAGE_PREFIX sets the image name prefix (default ArkOS_R3XS); DISTRIBUTION
# goes into manifest.json (default ArkOS).
# Needs: sfdisk, python3, erofs-utils (mkfs/fsck), xz; as root also attr
# (getfattr) and ext4/btrfs/erofs kernel support; rootless also fakeroot.
set -euo pipefail

image=$1 out=$2 version=$3 revision=$4
here=$(cd "$(dirname "$0")" && pwd)
prefix=${IMAGE_PREFIX:-ArkOS_R3XS}
MKFS=${MKFS_EROFS:-mkfs.erofs} FSCK=${FSCK_EROFS:-fsck.erofs}
part_bytes=$((2040 * 1024 * 1024))   # GitHub takes release files under 2 GiB only
case $version in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) echo "version must be 8 digits (MMDDYYYY)" >&2; exit 1 ;; esac
mkdir -p "$out"
out=$(cd "$out" && pwd)   # absolute: later steps cd into it
work=$(mktemp -d "$(dirname "$out")/work.XXXXXX")   # beside the output, never in it
src=$work/src new=$work/new
mkdir -p "$src" "$new"
src_loop= new_loop=
rootless=${A36_ROOTLESS:-}
[ -n "$rootless" ] || { [ "$(id -u)" = 0 ] && rootless=0 || rootless=1; }

cleanup() {
	if [ "$rootless" = 0 ]; then
		mountpoint -q "$new" && umount "$new"
		mountpoint -q "$src" && umount "$src"
		[ -z "$new_loop" ] || losetup -d "$new_loop" || :
		[ -z "$src_loop" ] || losetup -d "$src_loop" || :
	fi
	chmod -R u+rwX "$work" 2>/dev/null || :
	rm -rf "$work"
}
trap cleanup EXIT

# The root filesystem is the first Linux (type 83) partition of the MBR image,
# the same one the console picks.
read -r start sectors < <(sfdisk -J "$image" | python3 -I -c '
import json, sys
for p in json.load(sys.stdin)["partitiontable"]["partitions"]:
    if p["type"].lower() in ("83", "0fc63daf-8483-4772-8e79-3d69d8477de4"):
        print(p["start"], p["size"]); break
else:
    sys.exit("no Linux partition in the image")')
echo "root filesystem: start sector $start, $sectors sectors"
offset=$((start * 512))

# Read the magic numbers ourselves: no loop device needed to know the type.
fstype=$(python3 -I - "$image" "$offset" <<'PY'
import sys
f = open(sys.argv[1], "rb"); o = int(sys.argv[2])
def at(pos, n):
    f.seek(o + pos); return f.read(n)
if at(1080, 2) == b"\x53\xef": print("ext4")
elif at(65600, 8) == b"_BHRfS_M": print("btrfs")
else: print("unknown")
PY
)
echo "source filesystem: $fstype"
name=${prefix}_$version.erofs.img
# Same options the console uses when it converts an image itself, with the
# stronger lz4hc packer: smaller, and read back exactly like lz4.
opts=(-b4096 -zlz4hc -E^xattr-name-filter --preserve-mtime --quiet)

if [ "$rootless" = 0 ]; then
	src_loop=$(losetup --find --show --read-only --offset "$offset" --sizelimit $((sectors * 512)) "$image")
	case $fstype in
	btrfs) mount -t btrfs -o ro "$src_loop" "$src" 2>/dev/null ||
		mount -t btrfs -o ro,rescue=nologreplay "$src_loop" "$src" ;;
	ext4) mount -t ext4 -o ro,noload "$src_loop" "$src" ;;
	*) echo "unexpected root filesystem type: $fstype" >&2; exit 1 ;;
	esac
	[ -x "$src/bin/sh" ] || [ -L "$src/bin" ] || { echo "this does not look like a root filesystem" >&2; exit 1; }
	"$MKFS" "${opts[@]}" "$out/$name" "$src"
	"$FSCK" "$out/$name"
	new_loop=$(losetup --find --show --read-only "$out/$name")
	mount -t erofs -o ro "$new_loop" "$new"
	# What must be identical: kind, mode, owner, group, link target, size of every
	# file and link, modification time, extended attributes, and file contents.
	listing() {
		(cd "$1" && find . -xdev \( -type d -printf 'd %m %U %G %T@ %p\n' \) -o \
			\( -not -type d -printf '%y %m %U %G %s %T@ %l %p\n' \) | LC_ALL=C sort)
	}
	attrs() {
		(cd "$1" && getfattr -R -h -d -m - -e hex . 2>/dev/null | LC_ALL=C sort)
	}
	hashes() {
		(cd "$1" && find . -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum)
	}
	listing "$src" > "$work/src.list"; listing "$new" > "$work/new.list"
	cmp "$work/src.list" "$work/new.list" || { diff "$work/src.list" "$work/new.list" | head -40; echo "file listing differs" >&2; exit 1; }
	attrs "$src" > "$work/src.attr"; attrs "$new" > "$work/new.attr"
	cmp "$work/src.attr" "$work/new.attr" || { diff "$work/src.attr" "$work/new.attr" | head -40; echo "extended attributes differ" >&2; exit 1; }
	hashes "$src" > "$work/src.sha"; hashes "$new" > "$work/new.sha"
	cmp "$work/src.sha" "$work/new.sha" || { diff "$work/src.sha" "$work/new.sha" | head -40; echo "file contents differ" >&2; exit 1; }
	echo "verified: $(wc -l < "$work/src.list") entries, $(wc -l < "$work/src.sha") files identical"
	(cd "$src" && du -sxh . 2>/dev/null | sed 's/^/source size: /')
	umount "$new"; losetup -d "$new_loop"; new_loop=
	umount "$src"; losetup -d "$src_loop"; src_loop=
else
	[ "$fstype" = ext4 ] || { echo "without root only ext4 sources can be read ($fstype found)" >&2; exit 1; }
	python3 -I "$here/ext4tar.py" "$image" "$offset" "$work/root.tar" "$work/source.list"
	"$MKFS" "${opts[@]}" --tar=f "$out/$name" "$work/root.tar"
	rm -f "$work/root.tar"
	"$FSCK" "$out/$name"
	# Owners and device nodes need root to extract; fakeroot records them instead.
	fakeroot -s "$work/fakeroot.db" "$FSCK" --extract="$new" --preserve "$out/$name"
	fakeroot -i "$work/fakeroot.db" python3 -I "$here/verify.py" "$work/source.list" "$new"
	if grep -q ' xattr:' "$work/source.list"; then
		# fakeroot does not keep xattrs. Extract again as ourselves: user.* and
		# ACL xattrs come back for real; security.* and trusted.* need root.
		if grep ' xattr:' "$work/source.list" | grep -q -E '(^| |,|:)(security|trusted)\.'; then
			echo "source has security/trusted xattrs: run this as root to verify them" >&2; exit 1
		fi
		rm -rf "$new"; mkdir -p "$new"
		"$FSCK" --extract="$new" --xattrs --no-preserve-owner "$out/$name"
		python3 -I - "$work/source.list" "$new" <<'PY'
import hashlib, os, sys
n = 0
for line in open(sys.argv[1], encoding="utf-8", errors="surrogateescape"):
    base, sep, xa = line.rstrip("\n").partition(" xattr:")
    if not sep: continue
    path = base.split(" ", 2)[1]
    want = dict(kv.split("=", 1) for kv in xa.split(","))
    p = os.path.join(sys.argv[2], path)
    have = {k: hashlib.sha256(os.getxattr(p, k, follow_symlinks=False)).hexdigest() for k in os.listxattr(p, follow_symlinks=False)}
    if have != want: sys.exit("xattrs differ on %s" % path)
    n += 1
print("verified: xattrs on %d paths" % n)
PY
	else
		echo "verified: the source has no extended attributes, and the tar stream carried none"
	fi
fi

size=$(stat -c %s "$out/$name")
sum=$(sha256sum "$out/$name" | cut -d' ' -f1)
# Packed with xz for the download. Only cut into parts when the packed file is
# still too large for one release file.
xz -T0 -6 "$out/$name"
packed_size=$(stat -c %s "$out/$name.xz")
packed_sum=$(sha256sum "$out/$name.xz" | cut -d' ' -f1)
echo "image $size bytes, packed $packed_size bytes"
if [ "$packed_size" -gt "$part_bytes" ]; then
	(cd "$out" && split -b "$part_bytes" -d -a 3 --numeric-suffixes=1 "$name.xz" "$name.xz.")
	rm "$out/$name.xz"
fi

python3 -I "$here/manifest.py" "$out" "$name" "$size" "$sum" "$version" "$revision" "$here/hotfixes/$version" "$packed_size" "$packed_sum"
(cd "$out" && sha256sum -- * > "$work/sums")
mv "$work/sums" "$out/SHA256SUMS"
ls -la "$out"
