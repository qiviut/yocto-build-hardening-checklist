"""Static checks for the product-neutral upstream baseline artifacts."""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class BaselineArtifactTests(unittest.TestCase):
    def test_reference_fragments_are_product_neutral(self):
        local = (ROOT / "baseline/reference/local.conf").read_text(encoding="utf-8")
        layers = (ROOT / "baseline/reference/bblayers.conf.in").read_text(encoding="utf-8")
        self.assertIn('MACHINE = "qemux86-64"', local)
        self.assertIn('DISTRO = "nodistro"', local)
        self.assertIn("##OEROOT##/meta", layers)
        self.assertNotIn("SSTATE_SIG_KEY", local + layers)
        self.assertNotIn("BBLAYERS +=", local + layers)

    def test_mitigation_profile_contains_only_non_secret_controls(self):
        profile = (ROOT / "baseline/mitigation/offline-and-signed-sstate.conf").read_text(encoding="utf-8")
        self.assertIn('BB_NO_NETWORK = "1"', profile)
        self.assertIn('BB_STRICT_CHECKSUM = "1"', profile)
        self.assertIn('SSTATE_VERIFY_SIG = "1"', profile)
        self.assertNotIn("SSTATE_SIG_PASSPHRASE", profile)

    def test_documented_pins_are_present(self):
        text = (ROOT / "baseline/README.md").read_text(encoding="utf-8")
        self.assertIn("046a90b0e9b7b914b7a95aec579cdc3fc9c7617a", text)
        self.assertIn("f94ae3d6ba49aef86f497998c0e0232a5039510a", text)


if __name__ == "__main__":
    unittest.main()
