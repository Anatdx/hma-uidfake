#!/usr/bin/env python3
"""Lift the inode shadow block out of src/policy.c for the host test.

The block is compiled for the kernel only (it needs inodes), so the host test
needs it as a source of its own. It is extracted rather than copied on purpose: a
copy would go stale without anything noticing, and this refuses to produce
anything when the markers or the pieces they are supposed to contain are gone.
"""
import pathlib
import sys

BEGIN = "/* UF_SHADOW_BEGIN"
END = "/* UF_SHADOW_END */"
NEEDED = ("uf_shadow_open", "shadow_owner", "shadow_replace", "shadow_drop_id",
          "igrab(", "kstrdup(", "fops.owner", "uidfake_apk_remove")


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    src = (root / "src" / "inode_hook.c").read_text()
    if BEGIN not in src or END not in src:
        print("extract_shadow: the markers are gone from src/policy.c",
              file=sys.stderr)
        return 1
    body = src.split(BEGIN, 1)[1].split("\n", 1)[1].split(END, 1)[0]
    for need in NEEDED:
        if need not in body:
            print(f"extract_shadow: the block has no {need!r}", file=sys.stderr)
            return 1
    out = root / "build" / "shadow_block.inc"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body)
    print(f"extract_shadow: {len(body.splitlines())} lines -> "
          f"{out.relative_to(root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
