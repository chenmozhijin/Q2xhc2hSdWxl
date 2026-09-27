#!/usr/bin/env python3
"""把 Tailscale DERP 中继服务器 IP 同步到 Ruleset/Tailscale.list。

数据来源：https://login.tailscale.com/derpmap/default （公开接口，无需鉴权）

规则文件结构：
    DOMAIN-SUFFIX,tailscale.com      <- 标记行以上：手工维护，脚本原样保留
    ...
    # --- Tailscale DERP relay IPs (auto-generated below, do not edit) ---
    # ams - Amsterdam                 <- 标记行以下：每次运行全量重写
    IP-CIDR,176.58.93.147/32,no-resolve
    IP-CIDR6,2a00:dd80:3c::3d5/128,no-resolve

用法：
    python3 scripts/sync_tailscale_derp.py               # 联网获取并写入
    python3 scripts/sync_tailscale_derp.py derpmap.json  # 使用本地 JSON（离线调试/测试）
    python3 scripts/sync_tailscale_derp.py --check       # 只检查是否过期，不写入（过期退出码 1）
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import urllib.request
from pathlib import Path

DERP_MAP_URL = "https://login.tailscale.com/derpmap/default"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "Ruleset" / "Tailscale.list"

# 标记行：以上内容手工维护，以下内容由本脚本生成
MARKER = "# --- Tailscale DERP relay IPs (auto-generated below, do not edit) ---"

# 文件不存在时使用的默认头部
DEFAULT_HEADER = [
    "DOMAIN-SUFFIX,tailscale.com",
    "DOMAIN-SUFFIX,tailscale.io",
    "DOMAIN-SUFFIX,ts.net",
]

USER_AGENT = (
    "Q2xhc2hSdWxl-tailscale-derp-sync/1.0 "
    "(+https://github.com/chenmozhijin/Q2xhc2hSdWxl)"
)


def load_derp_map(source: str) -> dict:
    """从 URL 或本地文件读取 DERP map。"""
    if "://" in source:
        request = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    with open(source, "r", encoding="utf-8") as handle:
        return json.load(handle)


def render_cidr(value: object) -> str | None:
    """把 DERP 节点里的地址规范化为 CIDR 字符串，非法值返回 None。"""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if "/" in text:
            network = ipaddress.ip_network(text, strict=False)
            return f"{network.network_address.compressed}/{network.prefixlen}"
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    return f"{address.compressed}/{address.max_prefixlen}"


def _sort_key(cidr: str) -> tuple[int, int]:
    address = ipaddress.ip_address(cidr.split("/")[0])
    return (address.version, int(address))


def collect_regions(derp_map: dict) -> dict[str, dict]:
    """按地区聚合中继 IP：{region_code: {"name": str, "v4": [...], "v6": [...]}}。"""
    regions = derp_map.get("Regions") or {}
    if isinstance(regions, dict):
        regions = list(regions.values())

    grouped: dict[str, dict] = {}
    for region in regions:
        if not isinstance(region, dict):
            continue
        code = str(region.get("RegionCode") or region.get("RegionID") or "unknown")
        name = str(region.get("RegionName") or code)
        bucket = grouped.setdefault(code, {"name": name, "v4": set(), "v6": set()})
        for node in region.get("Nodes") or []:
            if not isinstance(node, dict):
                continue
            for field, key in (("IPv4", "v4"), ("IPv6", "v6")):
                cidr = render_cidr(node.get(field))
                if cidr:
                    bucket[key].add(cidr)
    return grouped


def build_section(grouped: dict[str, dict]) -> tuple[list[str], int]:
    """生成标记行及其以下的所有行，返回 (行列表, IP 总数)。"""
    lines = [MARKER]
    seen: set[str] = set()
    total = 0
    for code in sorted(grouped):
        bucket = grouped[code]
        v4 = [c for c in sorted(bucket["v4"], key=_sort_key) if c not in seen]
        v6 = [c for c in sorted(bucket["v6"], key=_sort_key) if c not in seen]
        if not v4 and not v6:
            continue
        seen.update(v4)
        seen.update(v6)
        lines.append(f"# {code} - {bucket['name']}")
        lines.extend(f"IP-CIDR,{cidr},no-resolve" for cidr in v4)
        lines.extend(f"IP-CIDR6,{cidr},no-resolve" for cidr in v6)
        total += len(v4) + len(v6)
    return lines, total


def render_file(output: Path, grouped: dict[str, dict]) -> tuple[str, int]:
    """读取已有文件的头部（标记行以上），拼出完整的新文件内容。"""
    header = DEFAULT_HEADER
    if output.exists():
        existing = output.read_text(encoding="utf-8")
        preserved = existing.split(MARKER, 1)[0].rstrip().splitlines()
        if preserved:
            header = preserved

    section, total = build_section(grouped)
    body = [*header, "", *section]
    return "\n".join(body).rstrip("\n") + "\n", total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "source",
        nargs="?",
        default=DERP_MAP_URL,
        help=f"DERP map 的 URL 或本地 JSON 文件（默认 {DERP_MAP_URL}）",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"输出的规则文件（默认 {DEFAULT_OUTPUT}）",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="只检查规则文件是否已是最新，不写入；过期时以退出码 1 结束",
    )
    args = parser.parse_args(argv)

    output = Path(args.output)

    try:
        derp_map = load_derp_map(args.source)
    except Exception as exc:  # noqa: BLE001 - 网络/JSON 错误都要给出可读提示
        print(f"错误：无法读取 DERP map（{args.source}）：{exc}", file=sys.stderr)
        return 1

    grouped = collect_regions(derp_map)
    content, total = render_file(output, grouped)
    if total == 0:
        print("错误：DERP map 中未解析到任何中继 IP，拒绝改写规则文件", file=sys.stderr)
        return 1

    current = output.read_text(encoding="utf-8") if output.exists() else None
    if current == content:
        print(f"{output} 已是最新（{total} 条中继 IP）")
        return 0

    if args.check:
        print(f"{output} 需要更新（{total} 条中继 IP）", file=sys.stderr)
        return 1

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8", newline="\n")
    print(f"已更新 {output}（{total} 条中继 IP，{len(grouped)} 个地区）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
