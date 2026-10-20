#!/usr/bin/env python3
"""index.json の機械検査。掲載の申請（PR）ごと・週次に動かす。標準ライブラリのみ（署名の検証だけ minisign コマンドを使う）。

使い方:
  validate.py [--index index.json] [--base-index <変更前の index.json>]

  --base-index を渡すと、リリースの検査（ネットワーク）は「追加・変更された行」だけにする。形式の検査は常に全行。
  渡さなければ全行のリリースを検査する（週次の点検・手元での確認）。

何を見るか:
  形式  : 本体の PluginCatalog.parse と同じ規則（id・repo・signerKeyId の書式、重複、行数・文字数の上限）に加え、
          申請では signerKeyId を必須にする（署名済みのリリースだけを載せる）。
  公式  : 公式鍵を名乗る行は repo の所有者が tatsunidas でなければ拒否。
  リリース: repo が公開で、最新の非 prerelease に zip・sha256・minisig・minisign.pub があり、sha256 が一致し、
          zip 直下の plugin.json の id が索引と一致・version がタグと一致・engines.graphy があり、
          署名が同梱の公開鍵で検証でき、その鍵 ID が索引の signerKeyId と一致する。

見ないもの: プラグインの中身（コード）の安全。ここを通ることは安全の保証ではない。
PR のコードは実行しない（索引は「データ」として読むだけ）。取得する zip は plugin.json だけを読み、サイズに上限をかける。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field

ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
REPO_RE = re.compile(r"[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}")
KEY_RE = re.compile(r"[0-9A-Fa-f]{16}")
MAX_ENTRIES = 1000
MAX_TEXT = 500
OFFICIAL_KEY = "98EA7C6BA2D50118"
OFFICIAL_OWNER = "tatsunidas"
MAX_ASSET_BYTES = 100 * 1024 * 1024
MAX_PLUGIN_JSON = 64 * 1024


@dataclass
class Release:
    """検査に渡すリリース。ネットワークを使わない試験でも同じ形で渡せる。"""

    tag: str
    assets: dict[str, bytes] = field(default_factory=dict)


def check_format(rows: object) -> tuple[list[dict], list[str]]:
    """全行の形式。壊れた行は理由を返し、通った行だけを返す。"""
    errors: list[str] = []
    if not isinstance(rows, dict) or not isinstance(rows.get("plugins"), list):
        return [], ['index.json は {"plugins": [...]} の形でなければならない']
    good: list[dict] = []
    seen: set[str] = set()
    for n, row in enumerate(rows["plugins"], 1):
        if n > MAX_ENTRIES:
            errors.append(f"{MAX_ENTRIES} 行を超えている")
            break
        label = f"#{n}" + (f" ({row.get('id')})" if isinstance(row, dict) and isinstance(row.get("id"), str) else "")
        if not isinstance(row, dict):
            errors.append(f"{label}: オブジェクトではない")
            continue
        problem = _row_problem(row)
        if problem is None and row["id"] in seen:
            problem = "id が重複している"
        if problem:
            errors.append(f"{label}: {problem}")
            continue
        seen.add(row["id"])
        good.append(row)
    return good, errors


def _row_problem(row: dict) -> str | None:
    rid = row.get("id")
    if not isinstance(rid, str) or not ID_RE.fullmatch(rid):
        return "id の書式が不正（小文字英数と . _ - 、64 文字まで）"
    name = row.get("name")
    if not isinstance(name, str) or not name.strip():
        return "name が必要"
    repo = row.get("repo")
    if not isinstance(repo, str) or not REPO_RE.fullmatch(repo):
        return "repo の書式が不正（owner/repo）"
    key = row.get("signerKeyId")
    if not isinstance(key, str) or not KEY_RE.fullmatch(key):
        return "signerKeyId が必要（16 桁の 16 進。署名済みのリリースだけを載せる）"
    for f in ("name", "description", "category", "minGraphy"):
        v = row.get(f)
        if v is not None and (not isinstance(v, str) or len(v) > MAX_TEXT):
            return f"{f} は {MAX_TEXT} 文字までの文字列"
    if key.upper() == OFFICIAL_KEY and repo.split("/")[0].lower() != OFFICIAL_OWNER:
        return "公式鍵（98EA7C6BA2D50118）を名乗れるのは tatsunidas のリポジトリだけ"
    return None


def key_id_from_minisig(sig: bytes) -> str:
    """minisig の 2 行目（base64: 2 バイトの方式 + 8 バイトの鍵 ID + 署名）から、minisign と同じ表記の鍵 ID を出す。"""
    lines = sig.decode("utf-8", "replace").replace("\r\n", "\n").split("\n")
    if len(lines) < 2:
        raise ValueError("minisig の形式が不正")
    blob = base64.b64decode(lines[1], validate=True)
    if len(blob) < 10:
        raise ValueError("minisig が短すぎる")
    return blob[2:10][::-1].hex().upper()


def check_release(row: dict, rel: Release) -> list[str]:
    """1 行ぶんのリリース検査。問題の一覧を返す（空なら合格）。"""
    problems: list[str] = []
    zips = [n for n in rel.assets if n.endswith(".zip")]
    if len(zips) != 1:
        return [f"zip の資産がちょうど 1 つ必要（見つかった数: {len(zips)}）"]
    zname = zips[0]
    for need in (f"{zname}.sha256", f"{zname}.minisig", "minisign.pub"):
        if need not in rel.assets:
            problems.append(f"資産 {need} が無い")
    if problems:
        return problems
    zdata = rel.assets[zname]

    # 完全性
    expected = rel.assets[f"{zname}.sha256"].decode("utf-8", "replace").split()
    actual = hashlib.sha256(zdata).hexdigest()
    if not expected or expected[0].lower() != actual:
        problems.append("sha256 が一致しない（zip が改ざんされたか、sha256 の資産が違う）")

    # plugin.json
    try:
        with zipfile.ZipFile(io.BytesIO(zdata)) as z:
            info = z.getinfo("plugin.json")
            if info.file_size > MAX_PLUGIN_JSON:
                problems.append("plugin.json が大きすぎる")
                pj = None
            else:
                pj = json.loads(z.read("plugin.json"))
    except KeyError:
        problems.append("zip の直下に plugin.json が無い")
        pj = None
    except (zipfile.BadZipFile, json.JSONDecodeError) as e:
        problems.append(f"zip または plugin.json を読めない: {e}")
        pj = None
    if isinstance(pj, dict):
        if pj.get("id") != row["id"]:
            problems.append(f"plugin.json の id（{pj.get('id')}）が索引の id（{row['id']}）と違う")
        if pj.get("version") != rel.tag.removeprefix("v"):
            problems.append(f"plugin.json の version（{pj.get('version')}）がタグ（{rel.tag}）と違う")
        eng = pj.get("engines")
        if not isinstance(eng, dict) or not eng.get("graphy"):
            problems.append("plugin.json に engines.graphy が無い")
    elif pj is not None:
        problems.append("plugin.json がオブジェクトではない")

    # 署名
    try:
        sig_key = key_id_from_minisig(rel.assets[f"{zname}.minisig"])
    except (ValueError, base64.binascii.Error) as e:
        problems.append(f"署名を読めない: {e}")
        return problems
    if sig_key != row["signerKeyId"].upper():
        problems.append(f"署名の鍵 ID（{sig_key}）が索引の signerKeyId（{row['signerKeyId'].upper()}）と違う")
    with tempfile.TemporaryDirectory() as d:
        paths = {}
        for key, name in (("zip", zname), ("sig", f"{zname}.minisig"), ("pub", "minisign.pub")):
            paths[key] = os.path.join(d, key)
            with open(paths[key], "wb") as f:
                f.write(rel.assets[name])
        try:
            r = subprocess.run(
                ["minisign", "-V", "-p", paths["pub"], "-m", paths["zip"], "-x", paths["sig"]],
                capture_output=True, text=True, timeout=60,
            )
        except FileNotFoundError:
            problems.append("minisign コマンドが無い（署名を検証できない）")
        else:
            if r.returncode != 0:
                problems.append("署名を同梱の公開鍵で検証できない: " + (r.stderr or r.stdout).strip().splitlines()[0])
    return problems


def _get(url: str, token: str | None, accept: str) -> bytes:
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "graphy-next-plugin-index-validate"})
    if token and url.startswith("https://api.github.com/"):
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as res:
        data = res.read(MAX_ASSET_BYTES + 1)
    if len(data) > MAX_ASSET_BYTES:
        raise ValueError("資産が大きすぎる")
    return data


def fetch_latest_release(repo: str, token: str | None) -> Release:
    """repo の最新の非 prerelease・非 draft のリリースと、その資産を取る（公開リポジトリのみ）。"""
    try:
        rels = json.loads(_get(f"https://api.github.com/repos/{repo}/releases?per_page=30", token, "application/vnd.github+json"))
    except urllib.error.HTTPError as e:
        raise ValueError(f"repo のリリースを取得できない（HTTP {e.code}。公開リポジトリか確認）") from e
    cands = [r for r in rels if not r.get("prerelease") and not r.get("draft")]
    if not cands:
        raise ValueError("公開されたリリース（prerelease でないもの）が無い")
    rel = max(cands, key=lambda r: r.get("published_at") or "")
    out = Release(tag=rel["tag_name"])
    for a in rel.get("assets", []):
        if a.get("size", 0) > MAX_ASSET_BYTES:
            raise ValueError(f"資産 {a.get('name')} が大きすぎる")
        out.assets[a["name"]] = _get(a["browser_download_url"], token, "application/octet-stream")
    return out


def changed_rows(rows: list[dict], base: object) -> list[dict]:
    """base（変更前の index.json）に無い・内容が変わった行。base が読めなければ全行。"""
    if not isinstance(base, dict) or not isinstance(base.get("plugins"), list):
        return rows
    old = {r.get("id"): r for r in base["plugins"] if isinstance(r, dict)}
    return [r for r in rows if old.get(r["id"]) != r]


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default="index.json")
    ap.add_argument("--base-index")
    args = ap.parse_args(argv)

    with open(args.index, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"NG index.json が JSON として読めない: {e}")
            return 1
    rows, errors = check_format(data)
    for e in errors:
        print(f"NG 形式 {e}")

    targets = rows
    if args.base_index:
        try:
            with open(args.base_index, encoding="utf-8") as f:
                targets = changed_rows(rows, json.load(f))
        except (OSError, json.JSONDecodeError):
            targets = rows
    token = os.environ.get("GITHUB_TOKEN")
    print(f"リリースを検査する行: {len(targets)} / {len(rows)}")
    for row in targets:
        try:
            problems = check_release(row, fetch_latest_release(row["repo"], token))
        except (ValueError, urllib.error.URLError, OSError) as e:
            problems = [str(e)]
        if problems:
            errors.extend(f"{row['id']}: {p}" for p in problems)
            for p in problems:
                print(f"NG {row['id']}: {p}")
        else:
            print(f"OK {row['id']} ({row['repo']})")
    print(f"\n{'合格' if not errors else '失敗'}: 問題 {len(errors)} 件")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
