# FaultLine — Physical AI Vulnerability Database

**Where software faults meet the physical world.**

FaultLine is an open, community-driven vulnerability database focused on **Physical AI** systems — humanoid robots, industrial robots, autonomous mobile robots (AMR), drones, service robots, autonomous vehicles, and the middleware, AI models, and edge hardware that power them.

**FaultLine is not a mirror of NVD.** It takes CVEs sourced from NVD, ZDI, vendor PSIRT advisories, GitHub Security Advisories, and CISA ICS advisories, and re-processes each one with domain-specific enrichment — turning a plain vulnerability advisory into actionable intelligence for robots, AMRs, humanoids, service robots, drones, industrial robots, and AV AI stacks. The approach mirrors what VicOne has already done for automotive with **AutoVulnDB**: take a generic CVE and translate it into "how does this actually get exploited on this class of physical system, and what happens in the real world when it does."

🔍 **[Browse the Vulnerability Explorer](https://robotichackingcommunity.com/physical-ai-vulnerability-database.html)** — search and filter by domain, vendor, and severity across the full dataset.

Sponsored by [VicOne Inc.](https://vicone.com)

---

## Why a Physical AI Vulnerability Database?

Physical AI — robots, drones, autonomous vehicles, and embodied agents that perceive, decide, and act in the physical world — is being deployed at scale across manufacturing, logistics, healthcare, agriculture, and defense. Unlike traditional IT vulnerabilities, a flaw in a Physical AI stack does not just leak data — **it can cause a robot to collide, a drone to crash, a manipulator arm to injure someone, or an autonomous vehicle to misjudge the road.** That's the fault line FaultLine tracks: the point where a software bug crosses over into physical consequence.

Yet today, vulnerability intelligence for this domain is fragmented and shallow:

- **Scattered across silos** — CVE/NVD, vendor PSIRT advisories, GitHub Security Advisories, academic papers, and conference talks (DEF CON, Black Hat, S4) each hold a piece of the picture, with no unified view.
- **Missing physical-world context** — standard CVE records describe software impact (confidentiality/integrity/availability) but say nothing about the resulting physical consequence: Will the robot fall? Will the drone lose control? Will a safety interlock be bypassed?
- **No attack-surface mapping to the Physical AI stack** — a vulnerability in DDS/ROS 2 middleware, a perception model, a motion planner, or an edge AI chip (e.g. NVIDIA Jetson) requires different mitigations, but generic vulnerability feeds don't map CVEs to this architecture.
- **Hard to correlate across an ecosystem of shared components** — the same ROS 2 / DDS / PX4 / firmware vulnerability can affect dozens of unrelated robot and drone vendors that build on the same open-source or commercial building blocks, but this fan-out is invisible in vendor-specific advisories.

**FaultLine closes this gap** by re-classifying and enriching public vulnerability data specifically through a Physical AI lens: mapping every CVE to a Physical AI domain and attack surface, reconstructing plausible attack chains, and describing the physical-world consequence — so that manufacturers, researchers, red teams, and defenders can reason about robot and embodied AI security the way they already reason about IT security.

## What's Inside

Each record in [`CVE-json/`](./CVE-json) is a single enriched vulnerability, structured as:

| Section | Description |
|---|---|
| `cve_id`, `title`, `description`, `cwe`, `cvss` | Core CVE metadata, including CVSS 3.1 score and an estimated CVSS 4.0 vector where applicable |
| `taxonomy` | Physical AI domain classification (with confidence + rationale), vendor, product, technical layer, attack surface, vulnerability class |
| `attack_chain` | Step-by-step reconstructed exploitation path(s) and the resulting physical consequence |
| `impact` | CIA impact plus `robot_safety_impact` and a plain-language list of `physical_world_impact` scenarios |
| `security_observations` | Root cause, underlying design issue, exploit precondition, and the generalizable security pattern |
| `mitigation` | Patch availability, workaround, and fix description |
| `affected_configurations` | Vendor/product/version/platform matrix |

Example — [`CVE-2024-0112`](./CVE-json/CVE-2024-0112.pavd.json), an NVIDIA Jetson/IGX Orin privilege escalation — is classified under **Cross-Domain Components** and **Embodied AI Agent**, with the reconstructed physical consequence: *"attacker can manipulate perception models, motion planning outputs, or disable safety inference, causing dangerous physical behavior in the robot."*

### Current Coverage (snapshot)

- **200** enriched vulnerability records (see [`index.json`](./index.json) for the full lightweight index)
- **Severity:** 32 Critical · 88 High · 69 Medium · 10 Low (CVSS-based)
- **Physical AI domains:** Robot Operating Systems & Middleware (54) · Cross-Domain Components (51) · Physical AI Infrastructure (43) · Embodied AI Agent (40) · Mobile Robot & AMR (26) · Service & Companion Robot (24) · Drone & Aerial Robotics (24) · Industrial Robot (19) · Humanoid Robot (14) · Autonomous Vehicle AI (1)
- **Notable vendors/projects tracked:** NVIDIA, ABB, eProsima (Fast DDS), Unitree Robotics, ECOVACS, RTI Connext DDS, PX4/ArduPilot, Mobile Industrial Robots, SICK, Open Robotics/ROS, Franka Robotics, Ghost Robotics, and more

This dataset grows continuously as new advisories are triaged and re-classified — coverage numbers above will drift; `index.json` is always the source of truth.

### Attack Surface & Supply Chain Coverage

Beyond top-level domains, every record is tagged with a `technical_layer`, so risk can be sliced by where in the stack a flaw actually lives — this is what makes FaultLine useful for supply-chain and SBOM triage, not just "which robot is affected":

Middleware / Communication Layer (54, e.g. ROS 2 / DDS / MAVLink) · Network / Connectivity (48) · Hardware / Firmware (42) · Robot OS / Development Tools (37) · Physical AI Infrastructure / MLOps (25) · Distribution / Supply Chain (9) · Mobile Companion App (8) · AI/ML Runtime / Inference (7) · AI/ML Training Pipeline (2)

Frequently recurring `cross_domain_tags` (useful as ready-made detection/threat-hunting labels) include `ROS2`, `DDS`, `PX4`, `ai-agent-framework`, `RPA`, `supply-chain`, `mass-fleet-attack`, and `map-tampering`.

### Case Studies

Two examples of how FaultLine turns a generic advisory into a physical-consequence-first record:

- **[CVE-2024-9876](./CVE-json/CVE-2024-9876.pavd.json) — ABB ANC Navigation Controller (Modification of Assumed-Immutable Data / CWE-471).** An authenticated attacker on the adjacent network can modify navigation data — maps, waypoints, safety-zone boundaries — that the AMR treats as immutable at runtime. FaultLine's reconstructed consequence: *"AMRs using the ANC for navigation receive corrupted map/path data... robots may enter restricted areas, fail to avoid obstacles, or collide with workers or infrastructure."* CVSS 3.1 tells you it's a 7.3/HIGH integrity issue; FaultLine tells you it's a warehouse-floor collision risk, and names the design fix (write-protect safety-critical navigation data, separate read/write authorization).
- **[CVE-2026-10557](./CVE-json/CVE-2026-10557.pavd.json) — Yarbo Mobile App Hard-Coded MQTT Credentials (CWE-798).** A single set of MQTT broker credentials is hard-coded into every copy of the Yarbo companion app and extractable via APK decompilation, granting wildcard-topic access to the entire global fleet's telemetry and command channels. FaultLine's reconstructed consequence: *"attacker gains real-time visibility and command execution over the entire global Yarbo autonomous lawn mower fleet; can direct robots into unsafe zones near children or pets."* This is the kind of supply-chain/companion-app/cloud-MQTT risk that a CVSS score alone (9.3/CRITICAL here) doesn't communicate to a product or risk-management audience.

### How FaultLine Differs from NVD / Generic CVE Feeds

| Dimension | NVD / generic CVE feed | FaultLine |
|---|---|---|
| Technical depth | Description + CVSS score | + reconstructed attack path, `physical_consequence`, `robot_safety_impact` |
| Domain focus | Generic, no product-class context | Explicit Physical AI domain + `technical_layer` tagging (middleware, firmware, MLOps, companion app, cloud, ...) |
| Actionability | Reader must infer exploitation path and mitigation | Attack chain and mitigation direction are pre-written |
| Supply-chain lens | Limited | Explicitly covers companion apps, middleware (ROS 2/DDS), cloud MQTT/OTA channels, and shared component fan-out across vendors |

## Possible Use Cases

FaultLine is designed to serve every stakeholder who needs to reason about security risk across the Physical AI lifecycle — from the engineer writing robot firmware to the regulator drafting the next AI safety standard.

| User Role | Scenario | How FaultLine Helps | Business Value |
|---|---|---|---|
| **Robot Manufacturer** | Assess newly disclosed vulnerabilities affecting products | Quickly identify affected robot models, AI components, firmware versions, attack surfaces, and mitigation guidance | Reduce vulnerability analysis time and accelerate patch deployment |
| **Product Security Incident Response Team (PSIRT)** | Analyze and respond to reported security issues | Provide enriched CVE information including root cause, attack path, references, exploit status, and remediation recommendations | Improve incident response efficiency and vulnerability prioritization |
| **Threat Intelligence Team** | Monitor emerging threats targeting Physical AI systems | Correlate CVEs with attack surfaces, AI pipelines, threat actors, exploit techniques, and related vulnerabilities | Generate actionable threat intelligence and proactive risk assessments |
| **Security Researcher** | Conduct vulnerability research and discover attack trends | Access enriched technical analysis, architecture mapping, related research papers, PoCs, and exploit references | Accelerate research and identify new attack vectors |
| **Penetration Tester / Red Team** | Plan offensive security assessments | Search vulnerabilities by robot platform, middleware, communication protocol, AI component, or sensor | Build realistic attack chains and prioritize high-impact testing scenarios |
| **SOC / MDR Team** | Develop detection and monitoring capabilities | Understand attack paths, indicators, affected protocols, and potential detection opportunities | Improve monitoring coverage and detection accuracy |
| **AI Safety Team** | Evaluate security risks across AI pipelines | Identify vulnerabilities affecting perception, planning, localization, manipulation, foundation models, and decision-making systems | Strengthen AI safety validation and reduce operational risks |
| **Robot Software Developer** | Secure software during development | Review historical vulnerabilities, secure coding references, mitigation guidance, and affected software versions | Prevent recurring security issues and improve software quality |
| **System Integrator** | Assess third-party components before deployment | Evaluate vulnerabilities across sensors, middleware, AI frameworks, operating systems, and hardware components | Reduce supply chain security risks |
| **Supply Chain Security Team** | Assess supplier security posture | Determine whether vendors are affected by known Physical AI vulnerabilities and verify mitigation status | Improve vendor risk management and procurement decisions |
| **Risk Management Team** | Perform product cybersecurity risk assessments | Map vulnerabilities to attack surfaces, physical impacts, and affected operational environments | Support enterprise risk analysis and investment decisions |
| **Compliance & Regulatory Team** | Demonstrate cybersecurity due diligence | Use vulnerability intelligence to support compliance with ISO/SAE 21434, IEC 62443, NIST CSF, EU CRA, and future AI regulations | Simplify compliance documentation and audit preparation |
| **Academic Researcher** | Study Physical AI security | Explore categorized vulnerabilities, attack taxonomy, exploit trends, and references to academic publications | Facilitate high-quality academic research and collaboration |
| **University Instructor** | Teach robot cybersecurity courses | Use real-world vulnerability cases, attack paths, mitigation strategies, and architecture diagrams | Improve cybersecurity education using practical examples |
| **Open Source Maintainer** | Secure robotics frameworks and AI libraries | Track vulnerabilities affecting ROS, ROS 2, DDS, AI frameworks, and related open-source components | Improve ecosystem security and community collaboration |
| **Cyber Insurance Provider** | Evaluate cyber risk for Physical AI products | Assess vulnerability exposure, exploit maturity, physical impact, and remediation readiness | Improve cyber insurance underwriting and risk modeling |
| **Government / National CERT** | Track vulnerabilities impacting national infrastructure | Monitor vulnerabilities affecting industrial robots, autonomous systems, healthcare robots, drones, and critical AI infrastructure | Support national cyber defense and coordinated vulnerability disclosure |
| **OEM / Automotive Manufacturer** | Assess cybersecurity risks in AI-powered vehicles | Identify vulnerabilities affecting onboard AI, ADAS, autonomous driving stacks, robotics platforms, and edge AI systems | Improve product security throughout the SDV lifecycle |
| **Digital Twin / Simulation Engineer** | Validate security before physical deployment | Map vulnerabilities into simulation environments to reproduce attack scenarios and verify mitigations | Reduce deployment risks through virtual security validation |

## Recommended Workflow

A few concrete ways to work FaultLine into an existing process, derived from the enrichment fields above:

1. **Design-time safety-boundary review.** Filter by `attack_surface` + `technical_layer` for your product class (e.g. "adjacent network + authenticated low-privilege → modifies navigation/safety data") and turn recurring patterns into architecture requirements — e.g. safety-critical data must have cryptographic integrity protection and separated write privileges. Feed the `attack_chain` into a red-team script and reproduce the behavioral deviation in simulation (e.g. Isaac Sim) or on hardware.
2. **Supply-chain / SBOM triage.** Filter by `domain` + `vendor` + `product` for third-party navigation controllers, ROS 2 packages, MQTT brokers, or companion apps you're integrating — prioritize by `physical_consequence`, not raw CVSS. A hard-coded-credential pattern like Yarbo's should trigger a design decision (per-device certificates, short-lived tokens) wherever a similar cloud-command channel exists in your own stack.
3. **Pre-deployment security testing & continuous monitoring.** Convert an `attack_chain` directly into a penetration-test script (e.g. "unpack companion app → extract broker credentials → command a target serial number"). Map `technical_layer` and `physical_consequence` against your threat model's attack layers (physical / perception / AI model / wireless / cloud) to check for coverage gaps.
4. **Threat hunting & incident response.** Use `cross_domain_tags` (`mass-fleet-attack`, `map-tampering`, `ros2-authentication`, ...) to seed detection rules; when a new advisory shares an attack surface with an existing FaultLine record (e.g. hard-coded credentials, unauthenticated physical port, writable navigation data), reuse its `physical_consequence` to triage worst-case impact immediately.
5. **Academic and open-source research.** Use `attack_chain` and `physical_world_impact` as grounded, real-world case material instead of purely theoretical attacks; compare `root_cause` across domains (AMR vs. humanoid vs. service robot) to surface cross-domain patterns (e.g. "safety-critical data treated as ordinary writable data"). Contribute enrichment for newly found issues back via pull request.
6. **Risk communication to non-technical stakeholders.** Translate "CVSS 7.3" into "this could let an AMR collide with a warehouse worker" for product, legal, insurance, and customer-facing conversations — and cite systematic Physical-AI-specific coverage in whitepapers, investor materials, or customer security assurances.

## Roadmap

- Broader zero-day and recently-disclosed advisory enrichment across all Physical AI domains.
- Coverage of AI-model-specific attack classes: adversarial examples against perception models, training-data/model poisoning, and backdoors in Vision-Language-Action (VLA) foundation models used for robot control.
- Continued index/site sync improvements for the [Vulnerability Explorer](https://robotichackingcommunity.com/physical-ai-vulnerability-database.html).

## Repository Structure

```
FaultLine/
├── CVE-json/            # One enriched *.pavd.json record per CVE (the source of truth)
├── index.json           # Lightweight generated index (cve_id, title, severity, domains, vendors, tags)
├── generate_index.py    # Rebuilds index.json by scanning CVE-json/
├── index.html           # Vulnerability Explorer — search & filter UI (GitHub Pages)
└── app.js               # Explorer front-end logic
```

## Getting Started

```bash
git clone git@github.com:robotichackingcommunity/PA_VD.git
cd PA_VD

# Rebuild index.json after adding/editing records in CVE-json/
pip install tqdm
python3 generate_index.py

# Browse the Explorer locally
python3 -m http.server 8000
# then open http://localhost:8000/index.html
```

## Contributing

New vulnerability records are welcome. To add one:

1. Create `CVE-json/<CVE-ID>.pavd.json` following the schema outlined in [What's Inside](#whats-inside) — use an existing record (e.g. `CVE-2024-0112.pavd.json`) as a template.
2. Fill in `taxonomy.physical_ai_domain` with a confidence score and a short rationale for each applicable domain.
3. Reconstruct at least one plausible `attack_chain` and describe the `physical_consequence`.
4. Run `python3 generate_index.py` to regenerate `index.json`.
5. Open a pull request.

Please cite primary sources (NVD, vendor advisories, GitHub Security Advisories) in the `source` field, and avoid speculative exploit details beyond what is publicly documented.

## Disclaimer

FaultLine aggregates and re-classifies **publicly disclosed** vulnerability information for defensive research, risk assessment, and education. Attack-chain reconstructions and physical-impact scenarios are analytical interpretations, not verified exploit demonstrations. This project does not publish or endorse offensive use against systems without authorization.

## License

See individual advisories for source attribution. Unless otherwise noted, the curated taxonomy, enrichment, and tooling in this repository are provided for research and educational use.

---

Maintained by the **FaultLine** project · Sponsored by [VicOne Inc.](https://vicone.com)
