#!/usr/bin/env python3
"""
SOC Lab Docker – Synthetic Log Generator
=========================================
Generates realistic security event logs and writes them as JSON to a
file-based output that Filebeat ships to Elasticsearch.

Event types:
  - authentication   (login success/failure/privilege escalation)
  - web_traffic      (HTTP requests and responses)
  - process_execution (process creation with parent/child relationships)
  - network          (connections, DNS queries, firewall events)
  - security_alerts  (AV, IDS, EDR detections)

Configuration via environment variables:
  LOG_OUTPUT_DIR        – Directory to write log files (default: /var/log/soc-lab)
  EVENT_RATE            – Events per second (default: 10)
  EVENT_TYPES           – Comma-separated enabled event types
  SYNTHETIC_USER_COUNT  – Number of synthetic user identities (default: 50)
  SYNTHETIC_HOST_COUNT  – Number of synthetic host identities (default: 20)
  LOG_LEVEL             – Logging verbosity: debug, info, warning (default: info)
"""

from __future__ import annotations

import json
import logging
import os
import random
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from faker import Faker

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("generator")

fake = Faker()
Faker.seed(0)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
CONFIG_FILE = BASE_DIR / "config.yaml"


def load_config() -> dict:
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return yaml.safe_load(f) or {}
    return {}


def load_template(name: str) -> dict:
    path = TEMPLATES_DIR / f"{name}.yaml"
    if path.exists():
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


class Config:
    def __init__(self) -> None:
        cfg = load_config()

        self.output_dir = Path(os.getenv("LOG_OUTPUT_DIR", cfg.get("output", {}).get("directory", "/var/log/soc-lab")))
        self.output_file = self.output_dir / "soc-lab-events.json"

        raw_rate = os.getenv("EVENT_RATE", str(cfg.get("rate", {}).get("events_per_second", 10)))
        self.events_per_second = float(raw_rate)
        self.interval = 1.0 / max(self.events_per_second, 0.001)

        raw_types = os.getenv(
            "EVENT_TYPES",
            "authentication,web_traffic,process_execution,network,security_alerts",
        )
        self.event_types = [t.strip() for t in raw_types.split(",") if t.strip()]

        self.user_count = int(os.getenv("SYNTHETIC_USER_COUNT", str(cfg.get("identities", {}).get("user_count", 50))))
        self.host_count = int(os.getenv("SYNTHETIC_HOST_COUNT", str(cfg.get("identities", {}).get("host_count", 20))))

        log_level = os.getenv("LOG_LEVEL", "info").upper()
        logger.setLevel(getattr(logging, log_level, logging.INFO))

        weights_cfg = cfg.get("event_weights", {})
        self.weights = {
            "authentication": weights_cfg.get("authentication", 35),
            "web_traffic": weights_cfg.get("web_traffic", 30),
            "process_execution": weights_cfg.get("process_execution", 20),
            "network": weights_cfg.get("network", 10),
            "security_alerts": weights_cfg.get("security_alerts", 5),
        }

        ratios = cfg.get("event_ratios", {})
        self.auth_ratios = ratios.get("authentication", {"success": 0.85, "failure": 0.13, "privilege_escalation": 0.02})
        self.web_ratios = ratios.get("web_traffic", {"2xx": 0.75, "3xx": 0.10, "4xx": 0.12, "5xx": 0.03})
        self.alert_ratios = ratios.get("security_alerts", {"antivirus": 0.40, "ids": 0.35, "edr": 0.25})


# ---------------------------------------------------------------------------
# Identity pool
# ---------------------------------------------------------------------------

class IdentityPool:
    """Deterministic pool of synthetic users and hosts for realistic correlations."""

    def __init__(self, user_count: int, host_count: int) -> None:
        self.users = [self._make_user() for _ in range(user_count)]
        self.hosts = [self._make_host(i) for i in range(host_count)]
        self.external_ips = [fake.ipv4_public() for _ in range(200)]
        self.internal_ips = [f"10.0.{random.randint(1,5)}.{random.randint(10,254)}" for _ in range(host_count)]

    @staticmethod
    def _make_user() -> dict:
        first = fake.first_name().lower()
        last = fake.last_name().lower()
        domain = random.choice(["CORP", "ACME", "LAB"])
        return {
            "name": f"{first}.{last}",
            "full_name": f"{first.capitalize()} {last.capitalize()}",
            "domain": domain,
            "email": f"{first}.{last}@{domain.lower()}.local",
        }

    @staticmethod
    def _make_host(idx: int) -> dict:
        role = random.choice(["workstation", "server", "dc", "web", "db", "fileserver"])
        os_type = random.choice(["windows", "linux"])
        if role in ("dc", "fileserver"):
            os_type = "windows"
        name = f"{role}-{idx+1:02d}"
        return {
            "name": name,
            "hostname": name.upper() if os_type == "windows" else name,
            "os": os_type,
            "role": role,
        }

    def random_user(self) -> dict:
        return random.choice(self.users)

    def random_host(self) -> dict:
        return random.choice(self.hosts)

    def random_external_ip(self) -> str:
        return random.choice(self.external_ips)

    def random_internal_ip(self) -> str:
        return random.choice(self.internal_ips)


# ---------------------------------------------------------------------------
# Base event builder
# ---------------------------------------------------------------------------

def base_event(category: str, action: str, outcome: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "@timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
        "event": {
            "category": [category],
            "action": action,
            "outcome": outcome,
            "kind": "event",
            "dataset": f"soc-lab.{category}",
        },
        "labels": {"lab": "soc-lab", "synthetic": True},
    }


# ---------------------------------------------------------------------------
# Event generators
# ---------------------------------------------------------------------------

def gen_authentication(pool: IdentityPool, cfg: Config, tmpl: dict) -> dict:
    ratios = cfg.auth_ratios
    roll = random.random()
    cumulative = 0.0
    subtype = "success"
    for sub, weight in ratios.items():
        cumulative += float(weight)
        if roll < cumulative:
            subtype = sub
            break

    user = pool.random_user()
    host = pool.random_host()
    src_ip = pool.random_external_ip() if random.random() < 0.3 else pool.random_internal_ip()

    outcome_map = {"success": "success", "failure": "failure", "privilege_escalation": "success"}
    ev = base_event("authentication", "logon" if subtype != "privilege_escalation" else "sudo", outcome_map[subtype])

    ev["user"] = {
        "name": user["name"],
        "domain": user["domain"],
        "full_name": user["full_name"],
        "email": user["email"],
    }
    ev["host"] = {
        "name": host["hostname"],
        "os": {"type": host["os"]},
    }
    ev["source"] = {"ip": src_ip, "port": random.randint(1024, 65535)}
    ev["destination"] = {"ip": pool.random_internal_ip(), "port": random.choice([22, 3389, 636, 389])}

    auth_method = random.choice(tmpl.get("auth_methods", ["password"]))
    logon_type = random.choice(tmpl.get("logon_types", ["interactive"]))
    service = random.choice(tmpl.get("services", ["sshd"]))

    ev["event"]["type"] = ["start"]
    ev["authentication"] = {
        "method": auth_method,
        "type": logon_type,
        "service": service,
        "subtype": subtype,
    }

    if subtype == "failure":
        ev["event"]["reason"] = random.choice([
            "Invalid credentials",
            "Account locked",
            "Password expired",
            "Access denied",
        ])
    elif subtype == "privilege_escalation":
        ev["process"] = {"command_line": random.choice(tmpl.get("escalation_commands", ["sudo su -"]))}
        ev["event"]["category"] = ["authentication", "privilege"]

    return ev


def gen_web_traffic(pool: IdentityPool, cfg: Config, tmpl: dict) -> dict:
    method = random.choice(tmpl.get("http_methods", ["GET", "POST"]))
    path = random.choice(tmpl.get("paths", ["/"]))
    user_agent = random.choice(tmpl.get("user_agents", ["Mozilla/5.0"]))
    server = random.choice(tmpl.get("servers", ["web-server-01"]))

    # Pick status code based on weights
    status_codes = tmpl.get("status_codes", {200: 60})
    code_list = list(status_codes.keys())
    code_weights = list(status_codes.values())
    status_code = random.choices(code_list, weights=code_weights, k=1)[0]

    outcome = "success" if status_code < 400 else "failure"
    ev = base_event("web", "http_request", outcome)

    ev["url"] = {
        "path": path,
        "full": f"https://{server}{path}",
        "domain": server,
    }
    ev["http"] = {
        "request": {
            "method": method,
            "bytes": random.randint(100, 2048),
        },
        "response": {
            "status_code": status_code,
            "bytes": random.randint(200, 50000),
        },
        "version": random.choice(["1.1", "2.0"]),
    }
    ev["source"] = {"ip": pool.random_external_ip(), "port": random.randint(1024, 65535)}
    ev["destination"] = {"ip": pool.random_internal_ip(), "port": random.choice([80, 443])}
    ev["user_agent"] = {"original": user_agent}
    ev["host"] = {"name": server}
    ev["event"]["duration"] = random.randint(1_000_000, 500_000_000)  # nanoseconds

    return ev


def gen_process_execution(pool: IdentityPool, cfg: Config, tmpl: dict) -> dict:
    host = pool.random_host()
    user = pool.random_user()
    os_type = host["os"]

    if os_type == "windows":
        parents = tmpl.get("windows_processes", {}).get("parent", ["explorer.exe"])
        children = tmpl.get("windows_processes", {}).get("child", ["cmd.exe"])
    else:
        parents = tmpl.get("linux_processes", {}).get("parent", ["bash"])
        children = tmpl.get("linux_processes", {}).get("child", ["sh"])

    parent_name = random.choice(parents)
    child_name = random.choice(children)

    suspicious_child = child_name in ["mimikatz.exe", "psexec.exe", "mshta.exe", "wscript.exe", "cscript.exe"]
    cmd_pool = tmpl.get("command_lines", {})
    if suspicious_child and random.random() < 0.7:
        cmd = random.choice(cmd_pool.get("suspicious", [child_name]))
    else:
        cmd = random.choice(cmd_pool.get("benign", [child_name]))

    ev = base_event("process", "process_started", "success")
    ev["event"]["type"] = ["start"]

    pid = random.randint(1000, 65535)
    ppid = random.randint(100, 999)

    ev["process"] = {
        "name": child_name,
        "executable": (f"C:\\Windows\\System32\\{child_name}" if os_type == "windows"
                       else f"/usr/bin/{child_name.rstrip('.exe')}"),
        "command_line": cmd,
        "pid": pid,
        "parent": {
            "name": parent_name,
            "pid": ppid,
            "executable": (f"C:\\Windows\\System32\\{parent_name}" if os_type == "windows"
                           else f"/usr/bin/{parent_name}"),
        },
        "working_directory": "C:\\Users\\Public" if os_type == "windows" else "/tmp",
    }
    ev["user"] = {"name": user["name"], "domain": user.get("domain", "")}
    ev["host"] = {"name": host["hostname"], "os": {"type": os_type}}

    if os_type == "windows":
        ev["process"]["integrity_level"] = random.choice(
            tmpl.get("integrity_levels", ["Medium"])
        )

    return ev


def gen_network(pool: IdentityPool, cfg: Config, tmpl: dict) -> dict:
    subtypes = ["connection", "dns_query", "firewall_block"]
    subtype = random.choices(subtypes, weights=[60, 30, 10], k=1)[0]

    host = pool.random_host()
    src_ip = pool.random_internal_ip()
    dst_ip = pool.random_external_ip() if random.random() < 0.6 else pool.random_internal_ip()

    ev = base_event("network", subtypes[subtypes.index(subtype)], "success" if subtype != "firewall_block" else "failure")

    if subtype == "dns_query":
        ev["event"]["action"] = "dns_query"
        domain = random.choice(tmpl.get("legitimate_domains", ["example.com"]))
        record_type = random.choice(tmpl.get("dns_types", ["A"]))
        ev["dns"] = {
            "question": {"name": domain, "type": record_type, "class": "IN"},
            "response_code": "NOERROR",
            "answers": [{"name": domain, "type": record_type, "data": fake.ipv4_public()}],
        }
        ev["source"] = {"ip": src_ip, "port": random.randint(1024, 65535)}
        ev["destination"] = {"ip": "8.8.8.8", "port": 53}
        ev["network"] = {"protocol": "dns", "transport": "udp"}
    else:
        ports_cfg = tmpl.get("ports", {})
        dst_port = random.choice(list(ports_cfg.keys())) if ports_cfg else 443
        service_name = ports_cfg.get(dst_port, "unknown") if ports_cfg else "https"

        protocol = random.choice(tmpl.get("protocols", ["tcp"]))
        direction = random.choice(tmpl.get("directions", ["outbound"]))

        ev["source"] = {"ip": src_ip, "port": random.randint(1024, 65535), "bytes": random.randint(100, 10_000_000)}
        ev["destination"] = {"ip": dst_ip, "port": dst_port, "bytes": random.randint(100, 5_000_000)}
        ev["network"] = {
            "protocol": service_name,
            "transport": protocol,
            "direction": direction,
            "bytes": random.randint(200, 15_000_000),
            "packets": random.randint(10, 10000),
        }

        if subtype == "firewall_block":
            ev["event"]["reason"] = "Policy violation"
            ev["rule"] = {"name": f"BLOCK-{random.choice(['MALWARE','SCAN','EXFIL'])}-{random.randint(1000,9999)}"}

    ev["host"] = {"name": host["hostname"]}
    return ev


def gen_security_alert(pool: IdentityPool, cfg: Config, tmpl: dict) -> dict:
    ratios = cfg.alert_ratios
    choices = list(ratios.keys())
    weights = [ratios[k] for k in choices]
    subtype = random.choices(choices, weights=weights, k=1)[0]

    host = pool.random_host()
    severity = random.choices(
        tmpl.get("severities", ["high", "medium", "low"]),
        weights=[5, 20, 40, 25, 10],
        k=1,
    )[0]

    ev = base_event("security_alert", f"{subtype}_detection", "success")
    ev["event"]["severity"] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}.get(severity, 2)
    ev["host"] = {"name": host["hostname"], "os": {"type": host["os"]}}

    if subtype == "antivirus":
        product = random.choice(tmpl.get("av_products", ["Windows Defender"]))
        malware = random.choice(tmpl.get("malware_names", ["Trojan.Generic"]))
        ev["threat"] = {
            "indicator": {"type": "file"},
            "software": {"name": malware, "type": "malware"},
        }
        ev["security"] = {
            "product": product,
            "action_taken": random.choice(["quarantined", "blocked", "cleaned", "deleted"]),
            "severity": severity,
            "malware_name": malware,
            "file_path": (
                f"C:\\Users\\{pool.random_user()['name']}\\AppData\\Temp\\{fake.file_name()}"
                if host["os"] == "windows"
                else f"/tmp/{fake.file_name()}"
            ),
        }

    elif subtype == "ids":
        product = random.choice(tmpl.get("ids_products", ["Snort"]))
        category = random.choice(tmpl.get("ids_categories", ["MALWARE-CNC"]))
        ev["security"] = {
            "product": product,
            "rule_name": f"{category} {fake.word().upper()} {random.randint(1000,9999)}",
            "severity": severity,
            "category": category,
            "action": random.choice(["alert", "block", "drop"]),
        }
        ev["source"] = {"ip": pool.random_external_ip(), "port": random.randint(1024, 65535)}
        ev["destination"] = {"ip": pool.random_internal_ip(), "port": random.choice([80, 443, 22, 3389])}
        ev["network"] = {"transport": "tcp"}

    elif subtype == "edr":
        vendor = random.choice(tmpl.get("edr_vendors", ["CrowdStrike Falcon"]))
        category = random.choice(tmpl.get("edr_categories", ["Execution"]))
        techniques = tmpl.get("mitre_techniques", {})
        technique_key = category.lower().replace(" ", "_")
        technique_list = techniques.get(technique_key, ["T1059"])
        technique = random.choice(technique_list)

        user = pool.random_user()
        ev["security"] = {
            "product": vendor,
            "category": category,
            "technique": technique,
            "severity": severity,
            "action": random.choice(["prevented", "detected", "quarantined"]),
        }
        ev["threat"] = {
            "technique": {"id": technique, "name": category},
            "tactic": {"name": category},
        }
        ev["user"] = {"name": user["name"]}
        ev["process"] = {
            "name": random.choice(["powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe"]),
            "pid": random.randint(1000, 65535),
            "command_line": random.choice([
                "powershell.exe -enc <base64>",
                "cmd.exe /c whoami",
                "wscript.exe malicious.js",
            ]),
        }

    return ev


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

class LogWriter:
    def __init__(self, output_file: Path) -> None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        self.output_file = output_file
        self._fh = open(output_file, "a", buffering=1)
        logger.info("Writing events to %s", output_file)

    def write(self, event: dict) -> None:
        self._fh.write(json.dumps(event) + "\n")

    def close(self) -> None:
        self._fh.flush()
        self._fh.close()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

GENERATORS = {
    "authentication": gen_authentication,
    "web_traffic": gen_web_traffic,
    "process_execution": gen_process_execution,
    "network": gen_network,
    "security_alerts": gen_security_alert,
}


def main() -> None:
    cfg = Config()

    logger.info("SOC Lab Log Generator starting")
    logger.info("Rate: %.1f events/sec | Types: %s", cfg.events_per_second, cfg.event_types)
    logger.info("Identities: %d users, %d hosts", cfg.user_count, cfg.host_count)

    pool = IdentityPool(cfg.user_count, cfg.host_count)
    writer = LogWriter(cfg.output_file)

    templates = {name: load_template(name) for name in cfg.event_types}

    # Filter weights to only enabled types
    active_weights = {k: v for k, v in cfg.weights.items() if k in cfg.event_types}
    type_keys = list(active_weights.keys())
    type_vals = list(active_weights.values())

    events_written = 0
    running = True

    def _shutdown(sig, frame):
        nonlocal running
        logger.info("Shutdown signal received – stopping generator")
        running = False

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    while running:
        loop_start = time.monotonic()

        event_type = random.choices(type_keys, weights=type_vals, k=1)[0]
        gen_fn = GENERATORS.get(event_type)
        if gen_fn:
            try:
                event = gen_fn(pool, cfg, templates.get(event_type, {}))
                writer.write(event)
                events_written += 1
                if events_written % 1000 == 0:
                    logger.info("Events written: %d", events_written)
            except Exception as exc:
                logger.warning("Error generating %s event: %s", event_type, exc)

        elapsed = time.monotonic() - loop_start
        sleep_time = cfg.interval - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)

    writer.close()
    logger.info("Generator stopped. Total events written: %d", events_written)


if __name__ == "__main__":
    main()
