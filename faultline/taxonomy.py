"""Controlled vocabulary for FaultLine records.

Every taxonomy value stored in CVE-json/ must be one of the canonical names
below.  Alias tables map historical / free-form spellings onto the canonical
names; anything that is not canonical and not an alias is a validation error.
"""
from __future__ import annotations

import re

# --------------------------------------------------------------------------
# Physical AI domains
# --------------------------------------------------------------------------
DOMAINS: tuple[str, ...] = (
    "Humanoid Robot",
    "Industrial Robot",
    "Mobile Robot & AMR",
    "Drone & Aerial Robotics",
    "Service & Companion Robot",
    "Autonomous Vehicle AI",
    "Embodied AI Agent",
    "Robot Operating Systems & Middleware",
    "Physical AI Infrastructure",
    "Cross-Domain Components",
)

DOMAIN_ALIASES: dict[str, str] = {
    "humanoid": "Humanoid Robot",
    "humanoid robots": "Humanoid Robot",
    "industrial robots": "Industrial Robot",
    "industrial robotics": "Industrial Robot",
    "mobile robot": "Mobile Robot & AMR",
    "amr": "Mobile Robot & AMR",
    "mobile robot / amr": "Mobile Robot & AMR",
    "mobile robots & amr": "Mobile Robot & AMR",
    "drone": "Drone & Aerial Robotics",
    "drones": "Drone & Aerial Robotics",
    "drone / aerial robotics": "Drone & Aerial Robotics",
    "drone & aerial robot": "Drone & Aerial Robotics",
    "service robot": "Service & Companion Robot",
    "service & companion robots": "Service & Companion Robot",
    "service / companion robot": "Service & Companion Robot",
    "autonomous vehicle": "Autonomous Vehicle AI",
    "autonomous vehicles": "Autonomous Vehicle AI",
    "av ai": "Autonomous Vehicle AI",
    "embodied ai": "Embodied AI Agent",
    "embodied ai agents": "Embodied AI Agent",
    "robot operating system & middleware": "Robot Operating Systems & Middleware",
    "robot operating systems and middleware": "Robot Operating Systems & Middleware",
    "ros & middleware": "Robot Operating Systems & Middleware",
    "middleware": "Robot Operating Systems & Middleware",
    "physical ai infra": "Physical AI Infrastructure",
    "infrastructure": "Physical AI Infrastructure",
    "cross-domain": "Cross-Domain Components",
    "cross domain components": "Cross-Domain Components",
    "cross-domain component": "Cross-Domain Components",
}

# Technical-layer names that were (incorrectly) used as domains.  When found in
# physical_ai_domain they are moved to technical_layer and replaced by the
# domain on the right.
LAYER_AS_DOMAIN_FALLBACK: dict[str, str] = {
    "AI/ML Runtime / Inference": "Physical AI Infrastructure",
    "AI/ML Training Pipeline": "Physical AI Infrastructure",
    "Physical AI Infrastructure / MLOps": "Physical AI Infrastructure",
    "Distribution / Supply Chain": "Physical AI Infrastructure",
    "Mobile Companion App": "Service & Companion Robot",
    "Hardware / Firmware": "Cross-Domain Components",
    "Network / Connectivity": "Cross-Domain Components",
    "Middleware / Communication Layer": "Robot Operating Systems & Middleware",
    "Robot OS / Development Tools": "Robot Operating Systems & Middleware",
}

# --------------------------------------------------------------------------
# Technical layers
# --------------------------------------------------------------------------
LAYERS: tuple[str, ...] = (
    "Hardware / Firmware",
    "Robot OS / Development Tools",
    "Middleware / Communication Layer",
    "Network / Connectivity",
    "Mobile Companion App",
    "AI/ML Runtime / Inference",
    "AI/ML Training Pipeline",
    "Physical AI Infrastructure / MLOps",
    "Distribution / Supply Chain",
)

LAYER_ALIASES: dict[str, str] = {
    # hardware / firmware family
    "firmware": "Hardware / Firmware",
    "hardware": "Hardware / Firmware",
    "hardware/firmware": "Hardware / Firmware",
    "firmware / embedded os": "Hardware / Firmware",
    "flight controller / firmware": "Hardware / Firmware",
    "flight controller / flight stack": "Hardware / Firmware",
    "robot firmware / os layer": "Hardware / Firmware",
    "firmware / cryptographic layer": "Hardware / Firmware",
    "safety systems": "Hardware / Firmware",
    "safety system": "Hardware / Firmware",
    "physical robot control": "Hardware / Firmware",
    "embedded": "Hardware / Firmware",
    # robot OS / dev tools
    "robot os": "Robot OS / Development Tools",
    "robot os / control logic": "Robot OS / Development Tools",
    "development tools": "Robot OS / Development Tools",
    "robot os/development tools": "Robot OS / Development Tools",
    "simulation / development tools": "Robot OS / Development Tools",
    # middleware
    "middleware": "Middleware / Communication Layer",
    "communication layer": "Middleware / Communication Layer",
    "middleware/communication layer": "Middleware / Communication Layer",
    "middleware / communication": "Middleware / Communication Layer",
    # network
    "network": "Network / Connectivity",
    "connectivity": "Network / Connectivity",
    "network/connectivity": "Network / Connectivity",
    "connectivity / wireless": "Network / Connectivity",
    "wireless communication / connectivity layer": "Network / Connectivity",
    "wireless": "Network / Connectivity",
    "cloud / connectivity": "Network / Connectivity",
    # companion app
    "companion app": "Mobile Companion App",
    "mobile app": "Mobile Companion App",
    "mobile companion app / control interface": "Mobile Companion App",
    "control interface": "Mobile Companion App",
    # AI/ML runtime
    "ai/ml runtime": "AI/ML Runtime / Inference",
    "ai/ml inference": "AI/ML Runtime / Inference",
    "ai / ml inference engine": "AI/ML Runtime / Inference",
    "ai/ml inference engine": "AI/ML Runtime / Inference",
    "inference": "AI/ML Runtime / Inference",
    "inference engine": "AI/ML Runtime / Inference",
    "model runtime": "AI/ML Runtime / Inference",
    "vision-language model (vlm) layer": "AI/ML Runtime / Inference",
    "vlm layer": "AI/ML Runtime / Inference",
    "ai / ml runtime / inference": "AI/ML Runtime / Inference",
    # training
    "training pipeline": "AI/ML Training Pipeline",
    "ai/ml training": "AI/ML Training Pipeline",
    "ai / ml training pipeline": "AI/ML Training Pipeline",
    # MLOps
    "mlops": "Physical AI Infrastructure / MLOps",
    "physical ai infrastructure": "Physical AI Infrastructure / MLOps",
    "infrastructure / mlops": "Physical AI Infrastructure / MLOps",
    "physical ai infrastructure/mlops": "Physical AI Infrastructure / MLOps",
    # supply chain
    "supply chain": "Distribution / Supply Chain",
    "distribution": "Distribution / Supply Chain",
    "distribution/supply chain": "Distribution / Supply Chain",
}

# --------------------------------------------------------------------------
# Vendors (canonical spellings for names that drifted)
# --------------------------------------------------------------------------
VENDOR_ALIASES: dict[str, str] = {
    # case / spelling splits surfaced after bulk enrichment
    "bentoml": "BentoML",
    "cursor": "Cursor",
    "docker": "Docker",
    "fanuc": "FANUC",
    "google": "Google",
    "mlflow": "MLflow",
    "ollama": "Ollama",
    "pilz": "Pilz",
    "pytorch": "PyTorch",
    "huggingface": "Hugging Face",
    "hugging face": "Hugging Face",
    # GitHub org slugs -> project names
    "ggml-org": "ggml (llama.cpp)",
    "keras-team": "Keras",
    "kedro-org": "Kedro",
    "axolotl-ai-cloud": "Axolotl",
    "state-spaces": "state-spaces (Mamba)",
    "nltk": "NLTK",
    "langchain-ai": "LangChain",
    "run-llama": "LlamaIndex",
    "mlc-ai": "MLC AI",
    "kvcache-ai": "KVCache.AI",
    "gpt-researcher": "GPT Researcher",
    "svc-develop-team": "svc-develop-team",
    # CPE / CNA spellings that leak in through upstream facts
    "ros": "Open Robotics",
    "ros 2": "Open Robotics",
    "ros2": "Open Robotics",
    "opennav": "Open Navigation",
    "open navigation (opennav)": "Open Navigation",
    "ros-navigation": "Open Navigation",
    "ros 2 navigation2 (ros-navigation)": "Open Navigation",
    "navigation2": "Open Navigation",
    "vllm-project": "vLLM Project",
    "vllm": "vLLM Project",
    "sglang project": "SGLang",
    "sgl-project": "SGLang",
    "dronecode": "PX4 Autopilot Project",
    "px4 (dronecode)": "PX4 Autopilot Project",
    "mobile industrial robots a/s": "Mobile Industrial Robots",
    "ntpd_driver_project": "ntpd_driver project",
    "tradr-project": "TRADR project",
    "ecovacs robotics": "ECOVACS",
    "ecovacs": "ECOVACS",
    "px4": "PX4 Autopilot Project",
    "px4 autopilot": "PX4 Autopilot Project",
    "px4 autopilot project": "PX4 Autopilot Project",
    "px4 (dronecode foundation)": "PX4 Autopilot Project",
    "px4 (dronecode foundation / auterion)": "PX4 Autopilot Project",
    "dronecode / px4 autopilot project": "PX4 Autopilot Project",
    "px4 (dronecode foundation) / mavlink protocol maintainers": "PX4 Autopilot Project",
    "moos project (themoos)": "MOOS-IvP project",
    "themoos (moos project)": "MOOS-IvP project",
    "moos-ivp project": "MOOS-IvP project",
    "moos project": "MOOS-IvP project",
    "open robotics / ros community": "Open Robotics",
    "open source robotics foundation": "Open Robotics",
    "open robotics / gazebo project": "Open Robotics",
    "open robotics": "Open Robotics",
    "osrf": "Open Robotics",
    "rti (real-time innovations)": "RTI (Real-Time Innovations)",
    "real-time innovations": "RTI (Real-Time Innovations)",
    "rti": "RTI (Real-Time Innovations)",
    "eprosima": "eProsima",
    "unitree": "Unitree Robotics",
    "unitree robotics": "Unitree Robotics",
    "nvidia corporation": "NVIDIA",
    "nvidia": "NVIDIA",
    "vllm project (vllm-project)": "vLLM Project",
    "vllm": "vLLM Project",
    "sglang (sgl-project / lmsys)": "SGLang Project",
    "abb ltd": "ABB",
    "abb": "ABB",
    "dji": "DJI",
    "ardupilot": "ArduPilot",
    "ardupilot project": "ArduPilot",
    "mobile industrial robots (mir)": "Mobile Industrial Robots",
    "mobile industrial robots": "Mobile Industrial Robots",
    "mir": "Mobile Industrial Robots",
}

SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")


def _key(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).lower()


def canonical_domain(value: str) -> str | None:
    """Return the canonical domain name, or None if unknown."""
    if value in DOMAINS:
        return value
    return DOMAIN_ALIASES.get(_key(value))


def canonical_layer(value: str) -> str | None:
    """Return the canonical technical-layer name, or None if unknown."""
    if value in LAYERS:
        return value
    return LAYER_ALIASES.get(_key(value))


def canonical_vendor(value: str) -> str:
    """Return the canonical vendor spelling (unknown vendors pass through)."""
    return VENDOR_ALIASES.get(_key(value), value.strip())


def severity_for_score(score: float | None, version: str = "3.1") -> str | None:
    if score is None:
        return None
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
