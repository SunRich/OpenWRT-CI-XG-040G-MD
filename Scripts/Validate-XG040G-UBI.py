#!/usr/bin/env python3
"""Read-only checks for the XG-040G-MD pbs05 U-Boot UBI/FIT layout."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zlib

BOARD = "nokia,xg-040g-md-ubi"
PROFILE = "nokia_xg-040g-md-ubi"
TARGET = "CONFIG_TARGET_DEVICE_airoha_an7581_DEVICE_" + PROFILE


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fdt(blob):
    require(len(blob) >= 40, "Truncated FDT header")
    magic, size, off, strings, _, version, _, _, strings_len, struct_len = struct.unpack_from(">10I", blob)
    require(magic == 0xD00DFEED and 17 <= version, "Invalid FDT header")
    require(40 <= size <= len(blob), "FDT exceeds image")
    require(off + struct_len <= size and strings + strings_len <= size, "FDT blocks exceed image")
    nodes, stack, end = {}, [], off + struct_len
    while off + 4 <= end:
        token = struct.unpack_from(">I", blob, off)[0]
        off += 4
        if token == 1:
            stop = blob.index(b"\0", off, end)
            stack.append(blob[off:stop].decode())
            off = (stop + 4) & ~3
            nodes["/" + "/".join(stack[1:])] = {}
        elif token == 2:
            require(bool(stack), "Unbalanced FDT nodes")
            stack.pop()
        elif token == 3:
            require(off + 8 <= end and bool(stack), "Invalid FDT property")
            length, name_off = struct.unpack_from(">II", blob, off)
            off += 8
            require(name_off < strings_len and off + length <= end, "FDT property exceeds block")
            start = strings + name_off
            stop = blob.index(b"\0", start, strings + strings_len)
            nodes["/" + "/".join(stack[1:])][blob[start:stop].decode()] = blob[off:off + length]
            off = (off + length + 3) & ~3
        elif token == 9:
            require(not stack, "Unclosed FDT node")
            return size, nodes
        else:
            require(token == 4, "Unknown FDT token")
    raise ValueError("FDT has no end token")


def strings(value):
    require(value.endswith(b"\0"), "Unterminated FDT string")
    return value[:-1].decode().split("\0")


def text(props, name):
    return strings(props[name])[0]


def number(value):
    require(len(value) in (4, 8), "Invalid FDT integer")
    return int.from_bytes(value, "big")


def check_config(path, seeds, theme=None):
    data = path.read_text()
    selected = re.findall(r"^(CONFIG_TARGET_DEVICE_\S+)=y$", data, re.M)
    require(selected == [TARGET], "Effective configuration must select only " + TARGET)
    enabled = set(re.findall(r"^(CONFIG_\S+)=y$", data, re.M))
    required = {"CONFIG_PACKAGE_fitblk", "CONFIG_PACKAGE_luci", "CONFIG_TARGET_airoha_an7581"}
    if theme:
        required.update({"CONFIG_PACKAGE_luci-theme-" + theme, "CONFIG_PACKAGE_luci-app-" + theme + "-config"})
    forbidden = set()
    for seed in seeds:
        for name, value in re.findall(r"^(CONFIG_PACKAGE_\S+)=(y|n)$", seed.read_text(), re.M):
            if value == "n":
                forbidden.add(name)
            elif name.startswith("CONFIG_PACKAGE_luci-app-") or name in {
                "CONFIG_PACKAGE_tailscale", "CONFIG_PACKAGE_wireguard-tools",
                "CONFIG_PACKAGE_luci-proto-wireguard", "CONFIG_PACKAGE_airoha-en7581-npu-firmware",
            }:
                required.add(name)
    # Hidden device-default packages may be built as m with per-device rootfs;
    # their installation is checked against the actual device manifest later.
    available = enabled | (set(re.findall(r"^(CONFIG_PACKAGE_fitblk)=m$", data, re.M)))
    require(required <= available, "Requested packages missing after defconfig: " + ", ".join(sorted(required - available)))
    require(not forbidden & enabled, "Disabled packages enabled: " + ", ".join(sorted(forbidden & enabled)))
    return {"profile": PROFILE, "required_packages": sorted(x.removeprefix("CONFIG_PACKAGE_") for x in required if x.startswith("CONFIG_PACKAGE_")),
            "disabled_packages": sorted(x.removeprefix("CONFIG_PACKAGE_") for x in forbidden)}


def check_image(path, rootfs_output=None):
    blob = path.read_bytes()
    fit_size, nodes = fdt(blob)
    images = {}
    for node, props in nodes.items():
        if not re.fullmatch(r"/images/[^/]+", node):
            continue
        if "data" in props:
            payload = props["data"]
        else:
            offset = number(props["data-position"]) if "data-position" in props else ((fit_size + 3) & ~3) + number(props["data-offset"])
            size = number(props["data-size"])
            require(offset >= fit_size and offset + size <= len(blob), node + " payload exceeds uploaded image")
            payload = blob[offset:offset + size]
        hashes = {}
        for child, hp in nodes.items():
            if child.rsplit("/", 1)[0] != node or "algo" not in hp:
                continue
            algo = text(hp, "algo")
            if algo == "crc32":
                digest = struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)
            else:
                require(algo in {"sha1", "sha256", "sha384", "sha512"}, "Unsupported hash " + algo)
                digest = hashlib.new(algo, payload).digest()
            require(digest == hp["value"], "FIT hash mismatch: " + child)
            hashes[algo] = digest.hex()
        require(bool(hashes), "Unhashed FIT image: " + node)
        images[node.split("/")[-1]] = (props, payload, hashes)
    config = nodes["/configurations/" + text(nodes["/configurations"], "default")]
    kernel = images[text(config, "kernel")]
    require(text(kernel[0], "type") == "kernel" and text(kernel[0], "arch") == "arm64", "Wrong kernel type/architecture")
    require(text(kernel[0], "compression") in {"gzip", "lzma", "none"}, "Unsupported kernel compression")
    loadables = strings(config.get("loadables", b"\0"))
    roots = [images[name] for name in loadables if name in images and text(images[name][0], "type") == "filesystem"]
    require(len(roots) == 1, "FIT configuration must reference one root filesystem loadable")
    require(text(roots[0][0], "compression") == "none" and roots[0][1][:4] == b"hsqs", "Expected uncompressed SquashFS rootfs payload")
    _, dt = fdt(images[text(config, "fdt")][1])
    compatible = strings(dt["/"]["compatible"])
    require(compatible[0] == BOARD, "Wrong embedded device tree: " + repr(compatible))
    partitions = {}
    for node, props in dt.items():
        if "label" not in props or "/nand@" not in node or "/partitions/" not in node:
            continue
        name = text(props, "label")
        require(len(props["reg"]) == 8, "Unexpected NAND partition cell geometry")
        partitions[name] = list(struct.unpack(">II", props["reg"]))
    require(partitions == {"all_flash": [0, 0x10000000], "bl2": [0, 0x20000], "ubi": [0x20000, 0xFFE0000]}, "NAND layout mismatch: " + repr(partitions))
    for node, props in dt.items():
        if "/nand@" in node and props.get("label") in {b"all_flash\0", b"bl2\0"}:
            require("read-only" in props, "Bootloader/all_flash alias must be read-only")
    volumes = {text(props, "volname"): props for props in dt.values() if "volname" in props}
    require({"fit", "fip", "bosa", "ri", "ubootenv", "ubootenv2"} <= volumes.keys(), "Required UBI volumes missing from device tree")
    require(dt["/chosen"]["rootdisk"] == volumes["fit"]["phandle"], "Root disk must reference the fit volume")
    require(len(blob) < 0xFFE0000 - 16 * 0x20000, "Image too large for UBI plus boot/identity volumes")
    if rootfs_output:
        rootfs_output.write_bytes(roots[0][1])
    return {"file": path.name, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest(),
            "compatible": compatible, "partitions": partitions,
            "images": {name: {"size": len(v[1]), "hashes": v[2]} for name, v in images.items()}}


def rootfs_manifest(rootfs, unsquashfs):
    """Read the installed database from the exact FIT rootfs, not root.orig."""
    for database, package_key, version_key in (
        ("usr/lib/opkg/status", "Package", "Version"),
        ("lib/apk/db/installed", "P", "V"),
    ):
        result = subprocess.run([str(unsquashfs), "-cat", str(rootfs), database],
                                capture_output=True, timeout=60)
        if result.returncode:
            continue
        packages = {}
        for stanza in result.stdout.decode().split("\n\n"):
            fields = dict(line.split(":", 1) for line in stanza.splitlines()
                          if ":" in line and not line.startswith((" ", "\t")))
            name = fields.get(package_key, "").strip()
            version = fields.get(version_key, "").strip()
            if not name or not version:
                continue
            if package_key == "Package" and fields.get("Status", "").split()[-1:] != ["installed"]:
                continue
            require(name not in packages, "Duplicate installed package: " + name)
            packages[name] = version
        require(bool(packages), "Empty or unsupported package database: " + database)
        return "".join(name + " - " + packages[name] + "\n" for name in sorted(packages)), database
    raise ValueError("Cannot read installed opkg/APK package database from FIT rootfs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--seed", type=Path, action="append", default=[])
    parser.add_argument("--theme", help="Validate the theme selected by the calling workflow")
    parser.add_argument("--image", type=Path)
    parser.add_argument("--manifest", type=Path, help="Device manifest, including renamed release assets")
    parser.add_argument("--unsquashfs", type=Path, help="Read packages from the actual FIT SquashFS payload")
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = {"validation": "pbs05-v2026.07-4-ubi-fit"}
    if args.config:
        report["config"] = check_config(args.config, args.seed, args.theme)
    if args.target_dir:
        candidates = list(args.target_dir.glob("*" + PROFILE + "-squashfs-sysupgrade.itb"))
        require(len(candidates) == 1, "Expected exactly one UBI sysupgrade ITB, got " + repr(candidates))
        args.image = candidates[0]
        # Multi-profile OpenWrt emits a generic root.orig manifest, which omits
        # device defaults such as fitblk. Generate this profile's manifest from
        # the package database inside its own, hash-verified FIT rootfs.
        require(args.unsquashfs, "--target-dir requires --unsquashfs for per-device package verification")
        args.manifest = args.target_dir / (args.image.name.removesuffix("-squashfs-sysupgrade.itb") + ".manifest")
    if args.unsquashfs:
        require(args.image and args.manifest, "--unsquashfs requires an image and manifest destination")
        with tempfile.TemporaryDirectory(prefix="xg040g-rootfs-") as directory:
            rootfs = Path(directory) / "root.squashfs"
            report["image"] = check_image(args.image, rootfs)
            manifest, database = rootfs_manifest(rootfs, args.unsquashfs)
        if args.target_dir:
            args.manifest.write_text(manifest)
        else:
            require(sorted(args.manifest.read_text().splitlines()) == sorted(manifest.splitlines()),
                    "Provided manifest differs from installed FIT rootfs packages")
        report["rootfs_package_database"] = database
    if args.manifest:
        packages = {line.split(" - ", 1)[0] for line in args.manifest.read_text().splitlines()}
        required = set(report.get("config", {}).get("required_packages", []))
        forbidden = set(report.get("config", {}).get("disabled_packages", []))
        require(required <= packages, "Packages absent from device manifest: " + repr(sorted(required - packages)))
        require(not forbidden & packages, "Disabled packages present in device manifest: " + repr(sorted(forbidden & packages)))
        report["manifest"] = {"file": args.manifest.name, "package_count": len(packages), "required_packages_present": sorted(required)}
    if args.image and "image" not in report:
        report["image"] = check_image(args.image)
    require(args.config or args.image, "Provide --config, --image or --target-dir")
    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(output)
    print(output, end="")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, UnicodeError, struct.error, subprocess.SubprocessError) as error:
        raise SystemExit("UBI compatibility check failed: " + str(error))
