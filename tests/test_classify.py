import unittest

from faultline.classify import classify
from faultline.sources.facts import empty_facts


def facts(title, desc, vendor=None, product=None):
    f = empty_facts("CVE-2026-1")
    f["title"], f["description"] = title, desc
    if vendor or product:
        f["affected"] = [{"vendor": vendor, "product": product, "versions": [], "platforms": []}]
    return f


class ClassifyTests(unittest.TestCase):
    def test_positive_triton(self):
        r = classify(facts(None, "NVIDIA Triton Inference Server contains a vulnerability in the HTTP server where an attacker could cause a stack overflow by sending a crafted request.", "nvidia", "triton_inference_server"))
        self.assertEqual(r["decision"], "accept", r)
        self.assertIn("AI/ML Runtime / Inference", r["proposed_layers"])

    def test_positive_ros2(self):
        r = classify(facts(None, "An issue in ROS 2 Humble rclcpp allows a local attacker to execute arbitrary code via the ros2 topic hz command."))
        self.assertEqual(r["decision"], "accept")
        self.assertEqual(r["proposed_domains"][0], "Robot Operating Systems & Middleware")

    def test_positive_vacuum(self):
        r = classify(facts(None, "ECOVACS DEEBOT robot vacuum firmware exposes an unauthenticated telnet service."))
        self.assertEqual(r["decision"], "accept")
        self.assertEqual(r["proposed_domains"][0], "Service & Companion Robot")

    def test_negative_robots_txt(self):
        r = classify(facts(None, "The plugin exposes robots.txt editing to unauthenticated users, allowing stored XSS."))
        self.assertEqual(r["decision"], "rejected", r)

    def test_negative_robot_framework(self):
        r = classify(facts(None, "Robot Framework before 7.0 allows arbitrary code execution via crafted test files."))
        self.assertEqual(r["decision"], "rejected", r)

    def test_negative_drone_ci(self):
        r = classify(facts(None, "Drone CI server before 2.1 allows an attacker to bypass authentication in the drone pipeline webhook."))
        self.assertEqual(r["decision"], "rejected", r)

    def test_negative_generic_wordpress(self):
        r = classify(facts(None, "The Contact Form WordPress plugin is vulnerable to SQL injection."))
        self.assertEqual(r["decision"], "rejected")

    def test_review_band(self):
        r = classify(facts(None, "A buffer overflow in the IMU driver allows a local user to crash the service."))
        self.assertIn(r["decision"], ("review", "rejected"))

    def test_rejected_state_wins(self):
        f = facts(None, "NVIDIA Triton Inference Server RCE")
        f["state"] = "REJECTED"
        self.assertEqual(classify(f)["decision"], "rejected")


if __name__ == "__main__":
    unittest.main()
