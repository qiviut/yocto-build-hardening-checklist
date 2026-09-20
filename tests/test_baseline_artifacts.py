"""Static checks for the product-neutral upstream baseline artifacts."""
from __future__ import annotations

import unittest
from pathlib import Path

from scripts import baseline_network_fixture, reference_baseline

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
        self.assertIn('SSTATE_MIRROR_ALLOW_NETWORK = "0"', profile)
        self.assertNotIn("SSTATE_SIG_PASSPHRASE", profile)

    def test_documented_pins_are_present(self):
        text = (ROOT / "baseline/README.md").read_text(encoding="utf-8")
        self.assertIn("046a90b0e9b7b914b7a95aec579cdc3fc9c7617a", text)
        self.assertIn("f94ae3d6ba49aef86f497998c0e0232a5039510a", text)

    def test_reference_effective_values_fail_closed(self):
        expected = reference_baseline.EXPECTED_VARIABLES["reference"].copy()
        self.assertEqual(reference_baseline.effective_mismatches("reference", expected), {})
        expected["MACHINE"] = "wrong-machine"
        mismatches = reference_baseline.effective_mismatches("reference", expected)
        self.assertEqual(mismatches["MACHINE"], {"expected": "qemux86-64", "actual": "wrong-machine"})

    def test_reference_environment_does_not_inherit_policy_overrides(self):
        environment = {
            "PATH": "/usr/bin",
            "MACHINE": "wrong-machine",
            "BB_NO_NETWORK": "1",
            "BB_ENV_PASSTHROUGH_ADDITIONS": "MACHINE BB_NO_NETWORK",
            "SSTATE_MIRROR_ALLOW_NETWORK": "1",
        }
        sanitized = reference_baseline.sanitized_environment(environment)
        self.assertEqual(sanitized, {"PATH": "/usr/bin"})

    def test_network_fixture_requires_expected_bytes(self):
        reference = {
            "outcome": "returned",
            "server_requests": 1,
            "downloaded_bytes_match": True,
        }
        baseline_network_fixture.validate_case(reference, "returned")
        reference["downloaded_bytes_match"] = False
        with self.assertRaises(AssertionError):
            baseline_network_fixture.validate_case(reference, "returned")

        mitigation = {
            "outcome": "NetworkAccess",
            "server_requests": 0,
            "downloaded_bytes_match": False,
        }
        baseline_network_fixture.validate_case(mitigation, "NetworkAccess")


if __name__ == "__main__":
    unittest.main()
