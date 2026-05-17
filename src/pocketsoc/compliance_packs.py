from __future__ import annotations

PACKS = {
    "home-lab": {"max_outdated_packages": 15, "deny_ports": ["23"]},
    "strict-mobile": {"max_outdated_packages": 3, "deny_ports": ["23", "5555", "21"]},
    "low-power": {"max_outdated_packages": 20, "deny_ports": ["23"]},
}
