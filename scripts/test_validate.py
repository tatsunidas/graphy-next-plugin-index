#!/usr/bin/env python3
"""validate.py の試験。ネットワークを使わず、試験のたびに使い捨ての minisign 鍵を作ってリリースを組み立てる（要 minisign）。

負例ごとに「1 か所だけ直した正例（対照）」が通ることを確かめ、負例が空振りでないことを担保する。
"""
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(__file__))
import validate as v  # noqa: E402


def gen_key(d: str, name: str) -> tuple[str, str, str]:
    sec, pub = os.path.join(d, f"{name}.key"), os.path.join(d, f"{name}.pub")
    subprocess.run(["minisign", "-G", "-W", "-f", "-p", pub, "-s", sec], check=True, capture_output=True)
    with open(pub, "rb") as f:
        text = f.read().decode()
    key_id = text.splitlines()[0].rsplit(" ", 1)[1]  # "untrusted comment: minisign public key <ID>"
    return sec, pub, key_id


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.a_sec, cls.a_pub, cls.a_id = gen_key(cls.tmp.name, "A")
        cls.b_sec, cls.b_pub, cls.b_id = gen_key(cls.tmp.name, "B")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def release(self, *, pid="demo", version="1.0.0", tag="v1.0.0", signer="A", pub="A", signed=True,
                tamper=False, sha_of_other=False, engines=True, extra_zips=0, plugin_json=True):
        pj = {"id": pid, "name": "Demo", "version": version}
        if engines:
            pj["engines"] = {"graphy": ">=0.1.0"}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            if plugin_json:
                z.writestr("plugin.json", json.dumps(pj))
            z.writestr("ui.js", "export function activate(){}")
        zdata = buf.getvalue()
        name = f"{pid}-{version}.zip"
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb") as f:
            f.write(zdata)
        assets = {name: zdata, f"{name}.sha256": (hashlib.sha256(b"x" if sha_of_other else zdata).hexdigest() + f"  {name}\n").encode()}
        if signed:
            sec = self.a_sec if signer == "A" else self.b_sec
            sig = os.path.join(self.tmp.name, name + ".minisig")
            subprocess.run(["minisign", "-S", "-s", sec, "-m", path, "-x", sig], check=True, capture_output=True, input=b"\n")
            with open(sig, "rb") as f:
                assets[f"{name}.minisig"] = f.read()
        with open(self.a_pub if pub == "A" else self.b_pub, "rb") as f:
            assets["minisign.pub"] = f.read()
        if tamper:
            buf2 = io.BytesIO()
            with zipfile.ZipFile(buf2, "w") as z:
                z.writestr("plugin.json", json.dumps(pj))
                z.writestr("ui.js", "// tampered")
            assets[name] = buf2.getvalue()
        for i in range(extra_zips):
            assets[f"other{i}.zip"] = zdata
        return v.Release(tag=tag, assets=assets)

    def row(self, **over):
        r = {"id": "demo", "name": "Demo", "repo": "someone/demo-plugin", "signerKeyId": self.a_id}
        r.update(over)
        return r

    def assertProblem(self, problems, needle):
        self.assertTrue(any(needle in p for p in problems), f"{needle!r} が問題の中に無い: {problems}")


class ReleaseChecks(Fixture):
    def test_control_good_release_passes(self):
        self.assertEqual(v.check_release(self.row(), self.release()), [])

    def test_id_mismatch(self):
        self.assertProblem(v.check_release(self.row(id="other"), self.release()), "id")
        self.assertEqual(v.check_release(self.row(id="other"), self.release(pid="other")), [])  # 対照

    def test_version_tag_mismatch(self):
        self.assertProblem(v.check_release(self.row(), self.release(tag="v2.0.0")), "タグ")

    def test_sha256_mismatch(self):
        self.assertProblem(v.check_release(self.row(), self.release(sha_of_other=True)), "sha256")

    def test_tampered_zip(self):
        probs = v.check_release(self.row(), self.release(tamper=True))
        self.assertProblem(probs, "sha256")
        self.assertProblem(probs, "署名")

    def test_signer_key_mismatch_with_index(self):
        # 鍵 B で署名・公開鍵も B（鍵ごとの差し替え）。索引は鍵 A を名乗っている
        self.assertProblem(v.check_release(self.row(), self.release(signer="B", pub="B")), "signerKeyId")
        self.assertEqual(v.check_release(self.row(signerKeyId=self.b_id), self.release(signer="B", pub="B")), [])  # 対照

    def test_signed_by_b_pub_is_a(self):
        self.assertProblem(v.check_release(self.row(), self.release(signer="B", pub="A")), "検証できない")

    def test_unsigned(self):
        self.assertProblem(v.check_release(self.row(), self.release(signed=False)), "minisig")

    def test_missing_engines(self):
        self.assertProblem(v.check_release(self.row(), self.release(engines=False)), "engines.graphy")

    def test_no_plugin_json(self):
        self.assertProblem(v.check_release(self.row(), self.release(plugin_json=False)), "plugin.json")

    def test_two_zips(self):
        self.assertProblem(v.check_release(self.row(), self.release(extra_zips=1)), "ちょうど 1 つ")


class FormatChecks(unittest.TestCase):
    KEY = "0123456789ABCDEF"

    def rows(self, *rs):
        return v.check_format({"plugins": list(rs)})

    def good(self, **over):
        r = {"id": "ok", "name": "OK", "repo": "a/b", "signerKeyId": self.KEY}
        r.update(over)
        return r

    def test_control_good(self):
        rows, errs = self.rows(self.good())
        self.assertEqual((len(rows), errs), (1, []))

    def test_each_bad_row_is_rejected_alone(self):
        for label, bad in {
            "id": self.good(id="Bad Id"), "name": self.good(name=" "), "repo": self.good(repo="not a repo"),
            "key 無し": {k: v_ for k, v_ in self.good().items() if k != "signerKeyId"},
            "key 書式": self.good(signerKeyId="zz"), "長い説明": self.good(description="x" * 501),
        }.items():
            rows, errs = self.rows(self.good(id="keep"), bad)
            self.assertEqual([r["id"] for r in rows], ["keep"], label)
            self.assertEqual(len(errs), 1, label)

    def test_duplicate_id(self):
        rows, errs = self.rows(self.good(), self.good())
        self.assertEqual((len(rows), len(errs)), (1, 1))

    def test_official_key_only_for_official_owner(self):
        rows, errs = self.rows(self.good(signerKeyId=v.OFFICIAL_KEY, repo="mallory/plugin"))
        self.assertEqual((len(rows), len(errs)), (0, 1))
        rows, errs = self.rows(self.good(signerKeyId=v.OFFICIAL_KEY.lower(), repo="tatsunidas/graphy-next-plugin-x"))  # 対照
        self.assertEqual((len(rows), errs), (1, []))
        rows, errs = self.rows(self.good(signerKeyId=v.OFFICIAL_KEY, repo="Tatsunidas/x"))  # 所有者の大文字小文字は同じ
        self.assertEqual((len(rows), errs), (1, []))

    def test_whole_file(self):
        for bad in ([], {"plugins": {}}, {"x": 1}):
            self.assertEqual(v.check_format(bad)[0], [])
            self.assertTrue(v.check_format(bad)[1])


class ChangedRows(unittest.TestCase):
    def test_only_added_or_changed(self):
        base = {"plugins": [{"id": "a", "x": 1}, {"id": "b", "x": 1}]}
        rows = [{"id": "a", "x": 1}, {"id": "b", "x": 2}, {"id": "c", "x": 1}]
        self.assertEqual([r["id"] for r in v.changed_rows(rows, base)], ["b", "c"])
        self.assertEqual(len(v.changed_rows(rows, None)), 3)


class MinisigKeyId(Fixture):
    def test_matches_minisign_display(self):
        rel = self.release()
        sig = next(b for n, b in rel.assets.items() if n.endswith(".minisig"))
        self.assertEqual(v.key_id_from_minisig(sig), self.a_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
