"""Runs every dzq/1.0 test vector through the reference verifier.

    python3 -m unittest discover -s reference/python/tests
"""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
VECTORS = os.path.join(ROOT, "vectors")
sys.path.insert(0, os.path.dirname(HERE))

from dzq import archive, dq, kel, merkle, verify  # noqa: E402
from dzq.experimental import promise as promise_ext  # noqa: E402
from dzq.typedoc import TypeDoc  # noqa: E402
from dzq.blake3 import blake3  # noqa: E402


def load(rel, binary=False):
    with open(os.path.join(VECTORS, rel), "rb" if binary else "r", **({} if binary else {"encoding": "utf-8", "newline": ""})) as f:
        return f.read()


MANIFEST = json.loads(load("manifest.json"))


def known(v):
    return {d.said: d for d in (TypeDoc(load(t)) for t in v.get("types", []))}


EXTENSIONS = {"promise": promise_ext.Extension}


def matches(case, result, expect):
    for k, v in expect.items():
        case.assertEqual(result.get(k), v, "%s: %r" % (k, result.get("reason")))


class Credentials(unittest.TestCase):
    def test_all(self):
        for v in MANIFEST["credentials"]:
            with self.subTest(v["name"]):
                seal = json.loads(load(v["seal"])) if "seal" in v else None
                kel_text = load(v["kel"]) if "kel" in v else None
                r = verify.check_credential(load(v["bundle"]), seal=seal, kel_text=kel_text, known=known(v))
                matches(self, r, v["expect"])


class Archives(unittest.TestCase):
    def test_all(self):
        for v in MANIFEST["archives"]:
            with self.subTest(v["name"]):
                try:
                    r = archive.check_dzq(load(v["file"], binary=True))
                except archive.ArchiveError as e:
                    r = {"valid": False, "code": "archive", "reason": str(e)}
                matches(self, r, v["expect"])


class Presentations(unittest.TestCase):
    def test_all(self):
        for v in MANIFEST["presentations"]:
            with self.subTest(v["name"]):
                now = None
                if "now" in v:
                    import datetime
                    now = datetime.datetime.fromisoformat(v["now"])
                ext = [EXTENSIONS[v["experimental"]]()] if "experimental" in v else []
                r = verify.verify_presentation(load(v["file"]), v["nonce"], now=now, known=known(v), extensions=ext)
                expect = dict(v["expect"])
                want = expect.pop("promise", None)
                matches(self, r, expect)
                if want is not None:
                    cert = next(c for c in r["credentials"] if c.get("type") == "dzq:promise")
                    self.assertEqual("usable" if cert.get("usable") else cert.get("why"), want)


class Conditions(unittest.TestCase):
    def test_all(self):
        for c in json.loads(load("conditions.json"))["conditions"]:
            with self.subTest(c["dq"][:40]):
                p = dq.parse(c["dq"])
                self.assertEqual(p is not None, c["parses"])
                if p is not None:
                    self.assertEqual(str(p), c["canonical"])
                    proved = set(c["proved"])
                    self.assertEqual(dq.holds(p, lambda leaf: str(leaf) in proved), c["holds"])


class Merkle(unittest.TestCase):
    def test_all(self):
        for t in json.loads(load("merkle.json"))["trees"]:
            leaves = [bytes.fromhex(l) for l in t["leaves"]]
            root = bytes.fromhex(t["root"])
            self.assertEqual(merkle.root(leaves), root)
            for i, p in enumerate(t["proofs"]):
                self.assertTrue(merkle.verify(root, leaves[i], p))
                if len(leaves) > 1:
                    self.assertFalse(merkle.verify(root, leaves[(i + 1) % len(leaves)], p))
                bad = dict(p, size=p["size"] + 1)
                self.assertFalse(merkle.verify(root, leaves[i], bad))


class KeripyInterop(unittest.TestCase):
    """KERI events signed by keripy (taken from keriox's own tests): a 2-of-3
    multisig inception, rotation and interaction. Shows the KEL verifier
    agrees with other KERI implementations, not only with itself."""

    def test_keripy_kel(self):
        with open(os.path.join(HERE, "keripy_multisig_kel.cesr"), encoding="utf-8") as f:
            text = f.read()
        view = kel.build_view(text)
        self.assertEqual(view.sn, 2)
        self.assertEqual(view.rejected, [])
        self.assertEqual(len(view.epochs), 2)
        head, tail = text.rsplit('"a":[]}-AAD', 1)
        broken = head + '"a":[ ]}-AAD' + tail
        self.assertEqual(kel.build_view(broken).sn, 1)


class Blake3(unittest.TestCase):
    def test_known(self):
        self.assertEqual(blake3(b"").hex(), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        self.assertEqual(blake3(b"abc").hex(), "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")


if __name__ == "__main__":
    unittest.main()
