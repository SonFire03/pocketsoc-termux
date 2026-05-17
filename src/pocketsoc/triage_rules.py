from __future__ import annotations


def auto_route(severity: str, source_check: str) -> dict:
    owner = "soc"
    status = "new"
    if severity == "high":
        status = "investigating"
        owner = "oncall"
    if source_check in {"network_info", "listening_ports", "outbound_connections"}:
        owner = "net-owner"
    if source_check in {"package_hygiene", "app_inventory"}:
        owner = "ops-owner"
    return {"owner": owner, "status": status}
