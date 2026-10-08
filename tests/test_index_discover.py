import json
import os
import tempfile
import unittest
from pathlib import Path

from faultline.index import build_stats, index_entry, readme_block, update_readme
from faultline import discover as disc_mod


class IndexTests(unittest.TestCase):
    def rec(self, cve, sev="HIGH", domains=("Industrial Robot",), layers=("Hardware / Firmware",), auto=False):
        r = {
            "cve_id": cve, "title": "t", "published": "2026-01-01", "cvss": {"score": 7.5, "severity": sev, "version": "3.1"},
            "cwe": {"id": "CWE-20"},
            "taxonomy": {"physical_ai_domain": [{"domain": d, "confidence": 0.9} for d in domains],
                          "technical_layer": [{"layer": l, "technologies": []} for l in layers],
                          "vendor": ["ABB"], "product": [{"name": "IRC5"}, "OmniCore"]},
            "cross_domain_tags": ["x"], "impact": {"robot_safety_impact": "HIGH"},
        }
        if auto:
            r["enrichment"] = {"method": "claude-auto", "reviewed": False}
        return r

    def test_entry_and_stats(self):
        e1 = index_entry(self.rec("CVE-2026-1"), "CVE-2026-1.pavd.json")
        e2 = index_entry(self.rec("CVE-2026-2", "LOW", ("Drone & Aerial Robotics", "Cross-Domain Components"), ("AI/ML Runtime / Inference",), auto=True), "CVE-2026-2.pavd.json")
        self.assertEqual(e1["products"], ["IRC5", "OmniCore"])
        self.assertEqual(e1["enrichment"], "curated")
        self.assertFalse(e2["reviewed"])
        s = build_stats([e1, e2])
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["layers"]["AI/ML Runtime / Inference"], 1)
        self.assertEqual(s["domains"]["Cross-Domain Components"], 1)
        self.assertEqual(s["severity"], {"HIGH": 1, "LOW": 1})
        self.assertEqual(s["unreviewed_auto_records"], 1)
        block = readme_block(s)
        self.assertIn("**2** enriched", block)
        self.assertIn("AI/ML Runtime / Inference (1)", block)

    def test_update_readme_replaces_block(self):
        s = build_stats([index_entry(self.rec("CVE-2026-1"), "f")])
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "README.md"
            p.write_text("# X\n\n### Current Coverage (snapshot)\n\nold\n\n### Case Studies\n\nkeep\n")
            self.assertTrue(update_readme(s, p))
            t = p.read_text()
            self.assertIn("<!-- stats:start -->", t)
            self.assertNotIn("old", t)
            self.assertIn("keep", t)
            self.assertFalse(update_readme(s, p))  # idempotent
            s2 = dict(s, total=99)
            self.assertTrue(update_readme(s2, p))
            self.assertEqual(p.read_text().count("<!-- stats:start -->"), 1)


class TriageTests(unittest.TestCase):
    def test_routing_and_rescoring(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["FAULTLINE_ROOT"] = d
            try:
                (Path(d) / "CVE-json").mkdir()
                (Path(d) / "CVE-json" / "CVE-2026-9.pavd.json").write_text(json.dumps({"cve_id": "CVE-2026-9"}))
                t = disc_mod.Triage()
                base = {"cve_id": "CVE-2026-1", "title": None, "description": "NVIDIA Triton Inference Server allows RCE", "affected": [], "cpes": [], "references": [], "cvss": []}
                t.consider(base, "test")
                t.consider(dict(base, cve_id="CVE-2026-2", description="WordPress plugin XSS"), "test")
                t.consider(dict(base, cve_id="CVE-2026-9"), "test")
                self.assertEqual(t.stats["accept"], 1)
                self.assertEqual(t.stats["rejected"], 1)
                self.assertEqual(t.stats["already_in_db"], 1)
                t.save()
                pending = json.loads((Path(d) / "data" / "queue" / "pending.json").read_text())
                self.assertIn("CVE-2026-1", pending)
                self.assertEqual(pending["CVE-2026-1"]["decision"], "accept")
                # re-run with changed text moves it between queues
                t2 = disc_mod.Triage()
                t2.consider(dict(base, description="robots.txt editing in a WordPress plugin"), "test")
                self.assertEqual(t2.stats["rescored"], 1)
                self.assertNotIn("CVE-2026-1", t2.queues["accept"])
            finally:
                del os.environ["FAULTLINE_ROOT"]


if __name__ == "__main__":
    unittest.main()
