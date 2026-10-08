import json
import unittest
from pathlib import Path

from faultline.refresh import apply_facts
from faultline.sources import ghsa, mitre, nvd
from faultline.sources.facts import merge_facts, pick_cvss

FIX = Path(__file__).parent / "fixtures"


def facts():
    n = nvd.parse(json.loads((FIX / "nvd_CVE-2024-0112.json").read_text())["vulnerabilities"][0])
    m = mitre.parse(json.loads((FIX / "mitre_CVE-2024-0112.json").read_text()))
    g = ghsa.parse(json.loads((FIX / "ghsa_CVE-2024-0112.json").read_text())[0])
    return n, m, g


class ParserTests(unittest.TestCase):
    def test_parsers(self):
        n, m, g = facts()
        self.assertEqual(n["vuln_status"], "Deferred")
        self.assertEqual(n["published"], "2025-02-12")
        self.assertEqual(m["cwes"][0], {"id": "CWE-20", "name": "Improper Input Validation"})
        self.assertEqual(m["ssvc"]["exploitation"], "none")
        self.assertEqual(g["ghsa_id"], "GHSA-fwf2-5x9w-mqc9")
        merged = merge_facts(n, m, g)
        self.assertEqual(merged["sources"], ["nvd", "mitre", "ghsa"])
        self.assertEqual(pick_cvss(merged)["score"], 7.5)
        self.assertEqual(pick_cvss(merged, "4.0")["version"], "3.1")  # falls back


class ApplyFactsTests(unittest.TestCase):
    def test_apply_updates_only_authoritative_fields(self):
        n, m, g = facts()
        merged = merge_facts(n, m, g)
        rec = {
            "cve_id": "CVE-2024-0112", "title": "T", "description": "curated text",
            "published": "2025-02-12", "last_modified": "2025-01-01", "vuln_status": None,
            "cwe": {"id": "CWE-20", "name": None},
            "cvss": {"version": "3.1", "score": 6.0, "severity": "MEDIUM", "vector": "x", "source": "y"},
            "source": {"nvd": "u"},
            "attack_chain": {"steps": ["keep"]},
        }
        new, changes = apply_facts(rec, merged)
        self.assertEqual(new["description"], "curated text")
        self.assertEqual(new["attack_chain"], {"steps": ["keep"]})
        self.assertEqual(new["vuln_status"], "Deferred")
        self.assertEqual(new["last_modified"], "2026-06-17")
        self.assertEqual(new["cvss"]["score"], 7.5)
        self.assertEqual(new["cvss"]["severity"], "HIGH")
        self.assertEqual(new["cwe"]["name"], "Improper Input Validation")
        self.assertEqual(new["source"]["github_advisory"], "https://github.com/advisories/GHSA-fwf2-5x9w-mqc9")
        self.assertTrue(new["affected_configurations"])
        self.assertEqual(new["cvss"]["ssvc"]["exploitation"], "none")
        self.assertTrue(changes)
        again, changes2 = apply_facts(new, merged)
        self.assertEqual(changes2, [])

    def test_v4_main_record_not_downgraded(self):
        n, m, g = facts()
        merged = merge_facts(n, m, g)
        rec = {"cve_id": "CVE-2024-0112", "cvss": {"version": "4.0", "score": 8.0, "severity": "HIGH", "vector": "CVSS:4.0/..."}}
        new, _ = apply_facts(rec, merged)
        self.assertEqual(new["cvss"]["version"], "4.0")
        self.assertEqual(new["cvss"]["score"], 8.0)


if __name__ == "__main__":
    unittest.main()


class FactsHelpersTests(unittest.TestCase):
    def test_cwe_names_merge(self):
        a = {"cve_id": "CVE-1", "cwes": [{"id": "CWE-502", "name": None}]}
        b = {"cve_id": "CVE-1", "cwes": [{"id": "CWE-502", "name": "Deserialization of Untrusted Data"}, {"id": "CWE-20", "name": "x"}]}
        m = merge_facts(a, b)
        self.assertEqual(m["cwes"], [{"id": "CWE-502", "name": "Deserialization of Untrusted Data"}, {"id": "CWE-20", "name": "x"}])

    def test_pick_advisory(self):
        from faultline.sources.facts import pick_advisory
        refs = ["https://nvd.nist.gov/vuln/detail/CVE-1", "https://github.com/sgl-project/sglang/tree/main", "https://github.com/sgl-project/sglang/security/advisories/GHSA-x"]
        self.assertEqual(pick_advisory(refs), "https://github.com/sgl-project/sglang/security/advisories/GHSA-x")
        self.assertEqual(pick_advisory(["https://nvd.nist.gov/x"]), None)
        self.assertEqual(pick_advisory(["https://github.com/a/b/tree/main", "https://example.com/post"]), "https://example.com/post")


class CnaAndStaleTests(unittest.TestCase):
    def test_cna_kept_and_estimate_marked_stale(self):
        facts = {"cve_id": "CVE-9", "cvss": [
            {"version": "3.1", "score": 9.8, "severity": "CRITICAL", "vector": "CVSS:3.1/N", "source": "nvd@nist.gov", "type": "nvd-primary"},
            {"version": "3.1", "score": 5.3, "severity": "MEDIUM", "vector": "CVSS:3.1/C", "source": "psirt@vendor", "type": "nvd-secondary"},
        ], "cwes": [], "references": [], "affected": []}
        rec = {"cve_id": "CVE-9", "cvss": {"version": "3.1", "score": 5.3, "severity": "MEDIUM", "vector": "CVSS:3.1/C", "cvss_4_0_estimated": {"score": 7.1}}}
        new, changes = apply_facts(rec, facts)
        self.assertEqual(new["cvss"]["score"], 9.8)
        self.assertEqual(new["cvss"]["cna"]["score"], 5.3)
        self.assertTrue(new["cvss"]["cvss_4_0_estimated"]["stale"])
        again, changes2 = apply_facts(new, facts)
        self.assertEqual(changes2, [])
