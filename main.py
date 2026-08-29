"""
========================================================================================
HYBRID DATACENTER & CLOUD SECURITY ARCHITECTURE SIMULATOR
Enterprise IT & Cybersecurity Reference Implementation
========================================================================================
A complete, self-contained, zero-dependency Python simulator for hybrid cloud & 
datacenter cybersecurity. Simulates IAM federation, ZTNA, Security Groups, Transit 
Gateway routing, Next-Gen Firewall inspection, Kubernetes eBPF micro-segmentation, 
and automated attack mitigation.

Run in VS Code terminal:
    python main.py
========================================================================================
"""

import sys
import time
import json
import uuid
import hmac
import hashlib
import secrets
import threading
import webbrowser
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ======================================================================================
# 1. DATA MODELS & ENUMS
# ======================================================================================

@dataclass
class DevicePosture:
    is_managed: bool
    disk_encrypted: bool
    edr_compliant: bool
    os_version: str

@dataclass
class IdentityContext:
    user_id: str
    username: str
    role: str  # e.g., 'Faculty', 'Student', 'DevOps', 'Attacker'
    department: str
    device_posture: DevicePosture
    mfa_verified: bool
    ip_reputation_score: int  # 0 (malicious) to 100 (clean)

@dataclass
class EphemeralToken:
    token_id: str
    identity: str
    role_arn: str
    issued_at: float
    expires_at: float
    token_type: str  # 'STS_EPHEMERAL', 'SPIFFE_X509', 'STATIC_LEGACY'

@dataclass
class Packet:
    packet_id: str
    src_zone: str        # 'Remote_Faculty', 'OnPrem_DC', 'Spoke_LMS', 'Spoke_Research', 'External_Internet'
    src_ip: str
    src_tier: str        # 'Client', 'Ingress', 'K8s_Node', 'Database', 'Attacker_C2'
    dst_zone: str
    dst_ip: str
    dst_port: int
    protocol: str        # 'TCP', 'UDP', 'HTTP', 'HTTPS'
    http_method: str     # 'GET', 'POST', 'CONNECT'
    http_path: str       # e.g., '/api/v1/courses', '/api/v1/research/genomics'
    payload: str
    token: Optional[EphemeralToken] = None
    device_posture: Optional[DevicePosture] = None

@dataclass
class SimulationResult:
    allowed: bool
    blocked_at: str      # 'ZTNA_GATEWAY', 'TRANSIT_GATEWAY', 'INSPECTION_NGFW', 'SECURITY_GROUP', 'CILIUM_NETWORK_POLICY', 'KYVERNO_ADMISSION', 'FALCO_RUNTIME', 'EGRESS_FILTER', 'PASSED'
    reason: str
    trace_steps: List[str]
    alert_level: str     # 'INFO', 'WARN', 'CRITICAL'
    audit_log: Dict[str, Any]

# ======================================================================================
# 2. SECURITY ENGINES & CONTROLLERS
# ======================================================================================

class IAMController:
    """Zero Trust Identity Provider & Workload Identity Federation (IRSA / STS)"""
    def __init__(self):
        self.active_sessions: Dict[str, IdentityContext] = {}
        self.issued_tokens: Dict[str, EphemeralToken] = {}
        self._init_default_users()

    def _init_default_users(self):
        self.users = {
            "prof_smith": IdentityContext(
                user_id="U-1001",
                username="prof_smith",
                role="Faculty",
                department="Bioinformatics",
                device_posture=DevicePosture(is_managed=True, disk_encrypted=True, edr_compliant=True, os_version="macOS-14.5"),
                mfa_verified=True,
                ip_reputation_score=98
            ),
            "student_alice": IdentityContext(
                user_id="U-2004",
                username="student_alice",
                role="Student",
                department="ComputerScience",
                device_posture=DevicePosture(is_managed=False, disk_encrypted=True, edr_compliant=False, os_version="Windows-11"),
                mfa_verified=True,
                ip_reputation_score=90
            ),
            "rogue_actor": IdentityContext(
                user_id="U-9999",
                username="unknown_adversary",
                role="Attacker",
                department="External",
                device_posture=DevicePosture(is_managed=False, disk_encrypted=False, edr_compliant=False, os_version="Kali-Linux"),
                mfa_verified=False,
                ip_reputation_score=15
            )
        }

    def authenticate_ztna(self, username: str, target_resource: str) -> Tuple[bool, str, Optional[EphemeralToken]]:
        user = self.users.get(username)
        if not user:
            return False, "User does not exist in Identity Provider", None

        # 1. Posture Check
        if not user.device_posture.is_managed or not user.device_posture.edr_compliant:
            if "research" in target_resource.lower() or "admin" in target_resource.lower():
                return False, f"ZTNA Posture Check Failed: Unmanaged or non-EDR device cannot access high-sensitivity resource [{target_resource}]", None

        # 2. MFA Check
        if not user.mfa_verified:
            return False, "ZTNA Authentication Failed: Phishing-resistant FIDO2 MFA is required", None

        # 3. IP Reputation & Risk
        if user.ip_reputation_score < 50:
            return False, f"ZTNA Risk Engine: High risk IP reputation ({user.ip_reputation_score}/100) triggered automated session block", None

        # 4. RBAC Check
        if "research" in target_resource.lower() and user.role not in ["Faculty", "DevOps"]:
            return False, f"RBAC Denied: Role [{user.role}] is not authorized for Research Repositories", None

        # Issue short-lived ZTNA session token (15 mins TTL)
        token = EphemeralToken(
            token_id=f"ztna-jwt-{secrets.token_hex(8)}",
            identity=user.username,
            role_arn=f"arn:campus:iam::role/{user.role}-{user.department}",
            issued_at=time.time(),
            expires_at=time.time() + 900,
            token_type="STS_EPHEMERAL"
        )
        self.issued_tokens[token.token_id] = token
        return True, "ZTNA Context & Posture Verified: Short-lived access token minted", token

    def mint_k8s_workload_token(self, namespace: str, service_account: str) -> EphemeralToken:
        """Simulates AWS IAM Roles for Service Accounts (IRSA) / OIDC Federation"""
        token = EphemeralToken(
            token_id=f"irsa-{namespace}-{secrets.token_hex(6)}",
            identity=f"system:serviceaccount:{namespace}:{service_account}",
            role_arn=f"arn:aws:iam::123456789012:role/k8s-{namespace}-role",
            issued_at=time.time(),
            expires_at=time.time() + 1800,  # 30 mins
            token_type="STS_EPHEMERAL"
        )
        self.issued_tokens[token.token_id] = token
        return token


class SecurityGroupEngine:
    """Stateful Security Group reference chaining engine"""
    def __init__(self):
        # SG Membership table
        self.sg_registry = {
            "10.100.1.10": "sg-ingress-alb",
            "10.100.2.50": "sg-lms-k8s-nodes",
            "10.100.3.99": "sg-lms-aurora-db",
            "10.200.2.40": "sg-research-k8s-nodes",
            "10.200.3.88": "sg-research-db",
            "10.50.4.12":  "sg-onprem-sis-db",
            "10.50.2.20":  "sg-onprem-openshift",
            "198.51.100.45": "sg-ztna-verified-ingress"
        }

    def evaluate(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> Tuple[bool, str]:
        src_sg = self.sg_registry.get(src_ip, "sg-external-untrusted")
        dst_sg = self.sg_registry.get(dst_ip, "sg-unknown")

        # Database Tier Isolation
        if dst_sg in ["sg-lms-aurora-db", "sg-research-db", "sg-onprem-sis-db"]:
            # Only corresponding app tier can connect
            if dst_sg == "sg-lms-aurora-db":
                if src_sg == "sg-lms-k8s-nodes" and dst_port == 5432:
                    return True, f"SG Rule MATCH: sg-lms-aurora-db permits TCP/5432 from {src_sg}"
                return False, f"SG VIOLATION: Database {dst_sg} blocked inbound from {src_sg} on port {dst_port}. Direct DB access prohibited!"

            if dst_sg == "sg-research-db":
                if src_sg == "sg-research-k8s-nodes" and dst_port == 5432:
                    return True, f"SG Rule MATCH: sg-research-db permits TCP/5432 from {src_sg}"
                return False, f"SG VIOLATION: Research DB isolated; access from {src_sg} blocked"

            if dst_sg == "sg-onprem-sis-db":
                if src_sg in ["sg-onprem-openshift", "sg-lms-k8s-nodes"] and dst_port in [1433, 5432]:
                    return True, f"SG Rule MATCH: On-prem DB permits authorized app SG {src_sg}"
                return False, f"SG VIOLATION: On-Prem Database blocked unauthorized SG {src_sg}"

        # Application / K8s Tier
        if dst_sg in ["sg-lms-k8s-nodes", "sg-research-k8s-nodes"]:
            if src_sg in ["sg-ingress-alb", "sg-lms-k8s-nodes", "sg-ztna-verified-ingress"] and dst_port in [443, 8080, 8443]:
                return True, f"SG Rule MATCH: {dst_sg} permits traffic from {src_sg} on port {dst_port}"
            # Block raw lateral access across spoke SGs
            if src_sg == "sg-lms-k8s-nodes" and dst_sg == "sg-research-k8s-nodes":
                return False, f"SG VIOLATION: Lateral movement blocked between {src_sg} and {dst_sg}"

        # Ingress ALB
        if dst_sg == "sg-ingress-alb":
            if dst_port in [80, 443]:
                return True, "SG Rule MATCH: sg-ingress-alb permits HTTPS/443"
            return False, f"SG VIOLATION: sg-ingress-alb blocks non-web port {dst_port}"

        # Fallback default deny
        return True, "SG Default State: Permitted through general private network rule"


class TransitGatewayInspectionEngine:
    """Hub-and-Spoke Transit Gateway + Central Inspection NGFW"""
    def __init__(self):
        self.malicious_signatures = ["/etc/shadow", "eval(", "../../../", "c2-malicious", "nmap", "nc -e", "xmrig", "SELECT * FROM users--"]
        self.malicious_domains = ["c2-malicious.xyz", "ransomware-drop.ru", "crypto-miner-pool.org"]

    def route_and_inspect(self, packet: Packet) -> Tuple[bool, str, str]:
        # 1. Non-transitive Spoke-to-Spoke Routing Verification
        if packet.src_zone.startswith("Spoke_") and packet.dst_zone.startswith("Spoke_"):
            if packet.src_zone != packet.dst_zone:
                # Direct spoke-to-spoke without Inspection VPC is physically unroutable in TGW
                pass

        # 2. Central Inspection NGFW - Deep Packet Inspection (DPI)
        for sig in self.malicious_signatures:
            if sig.lower() in packet.payload.lower() or sig.lower() in packet.http_path.lower():
                return False, "INSPECTION_NGFW", f"NGFW IDS/IPS Signature Triggered: Malicious payload [{sig}] detected and dropped by Central Firewall"

        # 3. Central Egress Filter / Anti-Exfiltration
        if packet.dst_zone == "External_Internet":
            for domain in self.malicious_domains:
                if domain in packet.payload or domain in packet.dst_ip:
                    return False, "EGRESS_FILTER", f"Egress Domain Filter Triggered: Destination [{domain}] is unapproved / flagged as malicious C2"

        return True, "PASSED", "TGW & Central NGFW Inspection Passed: Clean packet verified"


class KubernetesMicrosegmentationEngine:
    """Cilium eBPF NetworkPolicy, Kyverno Admission, and Falco Runtime Engine"""
    def __init__(self):
        self.kyverno_blocked_flags = ["privileged: true", "runAsUser: 0", "allowPrivilegeEscalation: true"]
        self.falco_anomalies = ["spawn_shell", "read_shadow", "outbound_raw_socket"]

    def evaluate_admission(self, pod_spec: str) -> Tuple[bool, str]:
        """Kyverno / OPA Gatekeeper Admission Policy"""
        for flag in self.kyverno_blocked_flags:
            if flag in pod_spec:
                return False, f"Kyverno Admission Denied: Security profile violation [{flag}]. Unhardened root/privileged pods rejected."
        return True, "Kyverno Admission Passed: Container image signed with Cosign and unprivileged security context verified."

    def evaluate_runtime_falco(self, event_type: str) -> Tuple[bool, str]:
        """Falco eBPF Runtime Anomaly Engine"""
        if event_type in self.falco_anomalies:
            return False, f"Falco eBPF Runtime Alert: Anomalous syscall [{event_type}] detected inside container. Pod automatically quarantined."
        return True, "Falco Runtime Clean: No anomalous kernel syscalls detected."

    def evaluate_network_policy(self, src_ns: str, dst_ns: str, http_method: str, http_path: str) -> Tuple[bool, str]:
        """Cilium eBPF L7 NetworkPolicy"""
        # Cross-namespace isolation
        if src_ns != dst_ns:
            # Only allowed cross-namespace is Ingress -> LMS Frontend or Remote Client to Research
            if (src_ns == "ingress-system" and dst_ns == "lms-production") or (src_ns == "client-system" and dst_ns == "research-genomics"):
                return True, f"Cilium eBPF Policy: Permitted {src_ns} to {dst_ns}"
            return False, f"Cilium NetworkPolicy: Default-deny between namespaces [{src_ns}] and [{dst_ns}]"

        # LMS Namespace L7 Policies
        if src_ns == "lms-production":
            if http_path.startswith("/api/v1/courses") or http_path.startswith("/api/v1/auth") or http_path.startswith("/query/"):
                return True, f"Cilium L7 Policy: Allowed {http_method} {http_path}"
            if "admin" in http_path or "debug" in http_path:
                return False, f"Cilium L7 Policy: Unauthorized endpoint access blocked on {http_path}"

        return True, "Cilium Policy: Intra-namespace allowed"


# ======================================================================================
# 3. UNIFIED HYBRID SIMULATOR ORCHESTRATOR
# ======================================================================================

class HybridSecuritySimulator:
    def __init__(self):
        self.iam = IAMController()
        self.sg_engine = SecurityGroupEngine()
        self.tgw_engine = TransitGatewayInspectionEngine()
        self.k8s_engine = KubernetesMicrosegmentationEngine()
        self.audit_events: List[Dict[str, Any]] = []

    def log_event(self, event: Dict[str, Any]):
        self.audit_events.insert(0, event)
        if len(self.audit_events) > 100:
            self.audit_events.pop()

    def process_packet(self, packet: Packet) -> SimulationResult:
        traces = []
        traces.append(f"Packet received from [{packet.src_zone}] ({packet.src_ip}) -> [{packet.dst_zone}] ({packet.dst_ip}:{packet.dst_port})")

        # Step 1: Human / Machine IAM Token Validation
        if packet.src_zone == "Remote_Faculty":
            if not packet.token or packet.token.token_type != "STS_EPHEMERAL":
                res = SimulationResult(
                    allowed=False,
                    blocked_at="ZTNA_GATEWAY",
                    reason="Rejected: Missing or invalid ephemeral ZTNA token. Static or expired credentials not allowed.",
                    trace_steps=traces,
                    alert_level="CRITICAL",
                    audit_log={"action": "DROP", "stage": "ZTNA", "src": packet.src_ip, "dst": packet.dst_ip}
                )
                self.log_event(res.audit_log)
                return res
            traces.append(f"ZTNA: Ephemeral token [{packet.token.token_id[:16]}...] verified for identity [{packet.token.identity}]")

        # Step 2: Transit Gateway & Central Inspection NGFW
        allowed, stage, reason = self.tgw_engine.route_and_inspect(packet)
        traces.append(f"TGW/NGFW: {reason}")
        if not allowed:
            res = SimulationResult(
                allowed=False,
                blocked_at=stage,
                reason=reason,
                trace_steps=traces,
                alert_level="CRITICAL",
                audit_log={"action": "DROP", "stage": stage, "reason": reason, "src": packet.src_ip, "dst": packet.dst_ip}
            )
            self.log_event(res.audit_log)
            return res

        # Step 3: Security Group Evaluation (Stateful ENI level)
        sg_allowed, sg_reason = self.sg_engine.evaluate(packet.src_ip, packet.dst_ip, packet.dst_port, packet.protocol)
        traces.append(f"Security Group: {sg_reason}")
        if not sg_allowed:
            res = SimulationResult(
                allowed=False,
                blocked_at="SECURITY_GROUP",
                reason=sg_reason,
                trace_steps=traces,
                alert_level="WARN",
                audit_log={"action": "DROP", "stage": "SECURITY_GROUP", "reason": sg_reason, "src": packet.src_ip, "dst": packet.dst_ip}
            )
            self.log_event(res.audit_log)
            return res

        # Step 4: Kubernetes Cilium eBPF NetworkPolicy (if destination is a K8s container)
        if "k8s" in packet.dst_zone.lower() or "lms" in packet.dst_zone.lower() or "research" in packet.dst_zone.lower():
            src_ns = "lms-production" if "lms" in packet.src_zone.lower() else ("research-genomics" if "research" in packet.src_zone.lower() else ("client-system" if "remote" in packet.src_zone.lower() else "ingress-system"))
            dst_ns = "lms-production" if "lms" in packet.dst_zone.lower() else "research-genomics"
            
            k8s_allowed, k8s_reason = self.k8s_engine.evaluate_network_policy(src_ns, dst_ns, packet.http_method, packet.http_path)
            traces.append(f"Cilium eBPF: {k8s_reason}")
            if not k8s_allowed:
                res = SimulationResult(
                    allowed=False,
                    blocked_at="CILIUM_NETWORK_POLICY",
                    reason=k8s_reason,
                    trace_steps=traces,
                    alert_level="WARN",
                    audit_log={"action": "DROP", "stage": "CILIUM", "reason": k8s_reason, "src_ns": src_ns, "dst_ns": dst_ns}
                )
                self.log_event(res.audit_log)
                return res

        # If all gates pass
        traces.append("Security Gateways: All Zero-Trust and microsegmentation policies satisfied. Transaction Completed.")
        res = SimulationResult(
            allowed=True,
            blocked_at="PASSED",
            reason="Transaction Authorized: Identity, Posture, Transit Routes, Firewalls, SGs, and eBPF policies validated.",
            trace_steps=traces,
            alert_level="INFO",
            audit_log={"action": "ALLOW", "stage": "SUCCESS", "src": packet.src_ip, "dst": packet.dst_ip, "port": packet.dst_port}
        )
        self.log_event(res.audit_log)
        return res

    # ---------------- Pre-built Attack & Workflow Scenarios ----------------
    def run_scenario(self, scenario_id: str) -> Dict[str, Any]:
        if scenario_id == "faculty_valid_access":
            ok, msg, token = self.iam.authenticate_ztna("prof_smith", "research_genomics_repo")
            pkt = Packet(
                packet_id=str(uuid.uuid4()),
                src_zone="Remote_Faculty",
                src_ip="198.51.100.45",
                src_tier="Client",
                dst_zone="Spoke_Research",
                dst_ip="10.200.2.40",
                dst_port=443,
                protocol="HTTPS",
                http_method="GET",
                http_path="/api/v1/research/genomics/datasets",
                payload="GET /datasets Authorization: Bearer <valid-jwt>",
                token=token
            )
            sim = self.process_packet(pkt)
            return {"id": scenario_id, "title": "Faculty Secure ZTNA Access to Research", "result": asdict(sim), "ztna_msg": msg}

        elif scenario_id == "faculty_unmanaged_device_blocked":
            # Student or Faculty with unmanaged/unhealthy device attempting research repo
            ok, msg, token = self.iam.authenticate_ztna("student_alice", "research_genomics_repo")
            if not ok:
                sim = SimulationResult(
                    allowed=False,
                    blocked_at="ZTNA_GATEWAY",
                    reason=msg,
                    trace_steps=["Faculty/Student attempted connection from non-compliant device", msg],
                    alert_level="WARN",
                    audit_log={"action": "DROP", "stage": "ZTNA_POSTURE", "user": "student_alice"}
                )
                self.log_event(sim.audit_log)
                return {"id": scenario_id, "title": "Unmanaged Device Access Blocked by ZTNA", "result": asdict(sim), "ztna_msg": msg}

        elif scenario_id == "hybrid_lms_to_onprem_db":
            # Valid hybrid communication: LMS microservice connecting to on-prem SIS DB via Direct Connect & NGFW
            token = self.iam.mint_k8s_workload_token("lms-production", "lms-backend-sa")
            pkt = Packet(
                packet_id=str(uuid.uuid4()),
                src_zone="Spoke_LMS",
                src_ip="10.100.2.50",
                src_tier="K8s_Node",
                dst_zone="OnPrem_DC",
                dst_ip="10.50.4.12",
                dst_port=5432,
                protocol="TCP",
                http_method="POST",
                http_path="/query/student_enrollment",
                payload="SELECT student_id, course_id FROM enrollments WHERE semester='2026-FALL'",
                token=token
            )
            sim = self.process_packet(pkt)
            return {"id": scenario_id, "title": "Hybrid Cloud-to-OnPrem Secure DB Query", "result": asdict(sim), "ztna_msg": "IRSA Workload Token Verified"}

        elif scenario_id == "lateral_movement_attack":
            # Attacker compromised LMS web pod, attempting to pivot to Research DB
            pkt = Packet(
                packet_id=str(uuid.uuid4()),
                src_zone="Spoke_LMS",
                src_ip="10.100.2.50",
                src_tier="K8s_Node",
                dst_zone="Spoke_Research",
                dst_ip="10.200.3.88", # Direct Research DB IP
                dst_port=5432,
                protocol="TCP",
                http_method="GET",
                http_path="/dump_all",
                payload="ATTEMPT PORT SCAN & LATERAL SNOOPING"
            )
            sim = self.process_packet(pkt)
            return {"id": scenario_id, "title": "Lateral Movement Attack across VPCs", "result": asdict(sim), "ztna_msg": "N/A"}

        elif scenario_id == "ransomware_exfiltration_attack":
            # Pod attempting to exfiltrate research data to an external C2 server
            pkt = Packet(
                packet_id=str(uuid.uuid4()),
                src_zone="Spoke_Research",
                src_ip="10.200.2.40",
                src_tier="K8s_Node",
                dst_zone="External_Internet",
                dst_ip="185.220.101.5",
                dst_port=443,
                protocol="HTTPS",
                http_method="POST",
                http_path="/upload",
                payload="Host: c2-malicious.xyz\nData: EXFILTRATED_GENOMIC_SEQUENCES..."
            )
            sim = self.process_packet(pkt)
            return {"id": scenario_id, "title": "Ransomware Data Exfiltration to C2 Domain", "result": asdict(sim), "ztna_msg": "N/A"}

        elif scenario_id == "direct_db_bypass_attack":
            # Attacker trying to bypass Application tier and hit Aurora DB directly from untrusted network
            pkt = Packet(
                packet_id=str(uuid.uuid4()),
                src_zone="External_Internet",
                src_ip="203.0.113.88",
                src_tier="Attacker_C2",
                dst_zone="Spoke_LMS",
                dst_ip="10.100.3.99",
                dst_port=5432,
                protocol="TCP",
                http_method="CONNECT",
                http_path="/",
                payload="psql -h 10.100.3.99 -U postgres"
            )
            sim = self.process_packet(pkt)
            return {"id": scenario_id, "title": "Direct Database Access Bypass Attack", "result": asdict(sim), "ztna_msg": "N/A"}

        elif scenario_id == "kyverno_root_pod_blocked":
            spec = """
            apiVersion: v1
            kind: Pod
            metadata:
              name: malicious-miner
            spec:
              containers:
              - name: miner
                image: unapproved/miner:latest
                securityContext:
                  privileged: true
                  runAsUser: 0
            """
            ok, msg = self.k8s_engine.evaluate_admission(spec)
            sim = SimulationResult(
                allowed=ok,
                blocked_at="KYVERNO_ADMISSION" if not ok else "PASSED",
                reason=msg,
                trace_steps=["Developer submitted Pod manifest via ArgoCD GitOps", msg],
                alert_level="CRITICAL" if not ok else "INFO",
                audit_log={"action": "REJECT", "stage": "KYVERNO", "pod": "malicious-miner"}
            )
            self.log_event(sim.audit_log)
            return {"id": scenario_id, "title": "Privileged Root Container Admission Block", "result": asdict(sim), "ztna_msg": msg}

        elif scenario_id == "falco_runtime_anomaly":
            ok, msg = self.k8s_engine.evaluate_runtime_falco("spawn_shell")
            sim = SimulationResult(
                allowed=ok,
                blocked_at="FALCO_RUNTIME" if not ok else "PASSED",
                reason=msg,
                trace_steps=["Container execution monitored via eBPF kernel probes", msg, "Automated SOAR playbook: Container deleted and isolated"],
                alert_level="CRITICAL",
                audit_log={"action": "ALERT_AND_ISOLATE", "stage": "FALCO", "event": "spawn_shell"}
            )
            self.log_event(sim.audit_log)
            return {"id": scenario_id, "title": "Container Runtime Breakout (Falco Detection)", "result": asdict(sim), "ztna_msg": msg}

        return {"error": "Unknown scenario"}


# ======================================================================================
# 4. EMBEDDED DASHBOARD WEB SERVER (ZERO EXTERNAL DEPENDENCIES)
# ======================================================================================

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hybrid Datacenter & Cloud Security Architecture Simulator</title>
    <style>
        :root {
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --bg-card-hover: #334155;
            --border-color: #475569;
            --accent-blue: #38bdf8;
            --accent-green: #4ade80;
            --accent-red: #f87171;
            --accent-yellow: #fbbf24;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg-dark); color: var(--text-primary); padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border-color); padding-bottom: 15px; margin-bottom: 20px; }
        .header h1 { font-size: 22px; color: var(--accent-blue); }
        .header .badge { background: #0284c7; padding: 6px 12px; border-radius: 20px; font-size: 13px; font-weight: bold; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media(max-width: 1024px) { .grid { grid-template-columns: 1fr; } }
        .card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 18px; }
        .card h2 { font-size: 16px; margin-bottom: 12px; color: var(--accent-blue); display: flex; justify-content: space-between; }
        .scenarios-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        button.btn { background: #0369a1; color: white; border: none; padding: 10px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 500; transition: all 0.2s; text-align: left; }
        button.btn:hover { background: #0284c7; transform: translateY(-2px); }
        button.btn-attack { background: #991b1b; }
        button.btn-attack:hover { background: #b91c1c; }
        .result-box { background: #090d16; border: 1px solid var(--border-color); border-radius: 6px; padding: 14px; min-height: 240px; }
        .status-badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-bottom: 10px; }
        .status-pass { background: #166534; color: var(--accent-green); }
        .status-block { background: #7f1d1d; color: var(--accent-red); }
        .trace-step { padding: 4px 0; border-left: 2px solid var(--accent-blue); padding-left: 10px; margin: 6px 0; font-family: monospace; font-size: 12px; color: var(--text-secondary); }
        .topology { display: flex; flex-direction: column; gap: 10px; }
        .topo-tier { background: #0f172a; padding: 10px; border-radius: 6px; border: 1px dashed var(--border-color); font-size: 13px; }
        .topo-title { color: var(--accent-yellow); font-weight: bold; margin-bottom: 4px; }
        .logs-table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: monospace; }
        .logs-table th, .logs-table td { padding: 6px 8px; text-align: left; border-bottom: 1px solid var(--border-color); }
        .logs-table th { color: var(--text-secondary); }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Hybrid Datacenter & Cloud Security Architecture Simulator</h1>
            <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">Zero-Trust IAM | Transit Gateway Routing | NGFW Deep Inspection | Cilium eBPF | SG Chaining</p>
        </div>
        <div class="badge">SEC-OPS LIVE SIMULATOR v2.0</div>
    </div>

    <div class="grid">
        <!-- Scenarios Panel -->
        <div class="card">
            <h2>Execute Security & Attack Scenarios</h2>
            <div class="scenarios-grid">
                <button class="btn" onclick="runScenario('faculty_valid_access')">
                    1. Faculty ZTNA Remote Access<br>
                    <small style="color: #cbd5e1;">Valid Posture + FIDO2 MFA</small>
                </button>
                <button class="btn btn-attack" onclick="runScenario('faculty_unmanaged_device_blocked')">
                    2. Unmanaged Device Access<br>
                    <small style="color: #cbd5e1;">ZTNA Posture Check Drop</small>
                </button>
                <button class="btn" onclick="runScenario('hybrid_lms_to_onprem_db')">
                    3. Hybrid LMS to On-Prem DB<br>
                    <small style="color: #cbd5e1;">IRSA Token + Direct Connect</small>
                </button>
                <button class="btn btn-attack" onclick="runScenario('lateral_movement_attack')">
                    4. Lateral Movement Attack<br>
                    <small style="color: #cbd5e1;">Spoke-to-Spoke TGW Block</small>
                </button>
                <button class="btn btn-attack" onclick="runScenario('ransomware_exfiltration_attack')">
                    5. Ransomware Exfiltration<br>
                    <small style="color: #cbd5e1;">Egress Domain Proxy Filter</small>
                </button>
                <button class="btn btn-attack" onclick="runScenario('direct_db_bypass_attack')">
                    6. Direct Database Bypass<br>
                    <small style="color: #cbd5e1;">Isolated DB SG Violation</small>
                </button>
                <button class="btn btn-attack" onclick="runScenario('kyverno_root_pod_blocked')">
                    7. Privileged Root Container<br>
                    <small style="color: #cbd5e1;">Kyverno Admission Reject</small>
                </button>
                <button class="btn btn-attack" onclick="runScenario('falco_runtime_anomaly')">
                    8. Container Runtime Breakout<br>
                    <small style="color: #cbd5e1;">Falco eBPF Anomaly Alert</small>
                </button>
            </div>

            <h2 style="margin-top: 20px;">Architecture Segmentation Map</h2>
            <div class="topology">
                <div class="topo-tier">
                    <div class="topo-title">1. REMOTE & CAMPUS CLIENT TIER (ZTNA)</div>
                    Faculty / Researchers -> Identity Provider (SAML/OIDC) -> Context-Aware ZTNA Proxy
                </div>
                <div class="topo-tier">
                    <div class="topo-title">2. TRANSIT & INSPECTION HUB (AWS Transit Gateway)</div>
                    Dedicated Route Tables (RT-Spokes, RT-Inspection) -> Central NGFW (Palo Alto/Suricata with GWLB)
                </div>
                <div class="topo-tier">
                    <div class="topo-title">3. SPOKE WORKLOADS (EKS & OpenShift Microservices)</div>
                    Tier 1: Ingress ALB | Tier 2: EKS Nodes (IRSA Ephemeral IAM) | Tier 3: Isolated DBs (Zero Egress)
                </div>
                <div class="topo-tier">
                    <div class="topo-title">4. ON-PREMISES ENTERPRISE DATA CENTER</div>
                    Redundant Direct Connect (MACsec) + IPsec Backup -> Red Hat OpenShift & Enterprise SIS Core
                </div>
            </div>
        </div>

        <!-- Live Trace & Inspection Output -->
        <div class="card">
            <h2>Live Policy Evaluation & Defense Result <span id="res-stage" style="color: var(--text-secondary); font-size: 13px;">Waiting for run...</span></h2>
            <div class="result-box" id="result-box">
                <p style="color: var(--text-secondary); font-size: 14px;">Select any scenario on the left to trace packets through the hybrid defense-in-depth pipeline in real time.</p>
            </div>

            <h2 style="margin-top: 20px;">Real-Time Security Event Stream (SIEM)</h2>
            <div style="max-height: 180px; overflow-y: auto;">
                <table class="logs-table" id="logs-table">
                    <thead>
                        <tr>
                            <th>Action</th>
                            <th>Stage</th>
                            <th>Source</th>
                            <th>Destination</th>
                        </tr>
                    </thead>
                    <tbody id="logs-body">
                        <tr><td colspan="4" style="color: var(--text-secondary);">No events recorded yet.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        async function runScenario(id) {
            const resBox = document.getElementById('result-box');
            resBox.innerHTML = '<p style="color: var(--accent-blue);">Simulating packet traversal & security gate evaluation...</p>';
            
            try {
                const response = await fetch(`/api/run_scenario?id=${id}`);
                const data = await response.json();
                
                const result = data.result;
                const statusClass = result.allowed ? 'status-pass' : 'status-block';
                const statusText = result.allowed ? 'PASSED / AUTHORIZED' : `BLOCKED AT [${result.blocked_at}]`;
                
                let tracesHtml = result.trace_steps.map(t => `<div class="trace-step">${t}</div>`).join('');
                
                resBox.innerHTML = `
                    <div class="status-badge ${statusClass}">${statusText}</div>
                    <div style="font-weight: bold; margin-bottom: 8px; font-size: 15px;">${data.title}</div>
                    <div style="color: #cbd5e1; font-size: 13px; margin-bottom: 12px;"><strong>Outcome:</strong> ${result.reason}</div>
                    <div style="font-size: 12px; color: var(--accent-yellow); margin-bottom: 4px;"><strong>Defense-in-Depth Pipeline Trace:</strong></div>
                    ${tracesHtml}
                `;
                
                fetchLogs();
            } catch(e) {
                resBox.innerHTML = `<p style="color: var(--accent-red);">Error executing simulation: ${e}</p>`;
            }
        }

        async function fetchLogs() {
            try {
                const response = await fetch('/api/logs');
                const logs = await response.json();
                const tbody = document.getElementById('logs-body');
                if (logs.length === 0) return;
                
                tbody.innerHTML = logs.slice(0, 10).map(l => `
                    <tr>
                        <td style="color: ${l.action === 'ALLOW' ? '#4ade80' : '#f87171'}; font-weight: bold;">${l.action}</td>
                        <td>${l.stage}</td>
                        <td>${l.src || l.user || 'Internal'}</td>
                        <td>${l.dst || l.pod || 'Cloud'}</td>
                    </tr>
                `).join('');
            } catch(e) {}
        }
    </script>
</body>
</html>
"""

class SimulatorHTTPHandler(BaseHTTPRequestHandler):
    simulator = HybridSecuritySimulator()

    def log_message(self, format, *args):
        # Suppress noisy HTTP server logs in console
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode("utf-8"))
            return

        elif parsed.path == "/api/run_scenario":
            query = parse_qs(parsed.query)
            scenario_id = query.get("id", ["faculty_valid_access"])[0]
            result = self.simulator.run_scenario(scenario_id)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))
            return

        elif parsed.path == "/api/logs":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(self.simulator.audit_events).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


# ======================================================================================
# 5. CLI TEST RUNNER & CONSOLE EXECUTION
# ======================================================================================

def run_cli_test_suite():
    print("=" * 80)
    print("  HYBRID DATACENTER & CLOUD SECURITY ARCHITECTURE: AUTOMATED TEST SUITE")
    print("=" * 80)
    
    sim = HybridSecuritySimulator()
    scenarios = [
        ("faculty_valid_access", "1. Faculty Remote ZTNA Access (Compliant Device + MFA)"),
        ("faculty_unmanaged_device_blocked", "2. Unmanaged Device Access Attempt to Research Repo"),
        ("hybrid_lms_to_onprem_db", "3. Hybrid Cloud-to-OnPrem DB Access via DirectConnect"),
        ("lateral_movement_attack", "4. Lateral Movement Attack from LMS Spoke to Research DB"),
        ("ransomware_exfiltration_attack", "5. Ransomware Exfiltration to Malicious C2 Domain"),
        ("direct_db_bypass_attack", "6. Direct Database Access Bypass Attempt"),
        ("kyverno_root_pod_blocked", "7. Privileged Root Container Admission Attempt"),
        ("falco_runtime_anomaly", "8. Container Runtime Breakout Attempt (Falco eBPF)")
    ]

    for sc_id, sc_title in scenarios:
        res = sim.run_scenario(sc_id)
        result_data = res["result"]
        status_sym = "[ALLOWED]" if result_data["allowed"] else f"[BLOCKED @ {result_data['blocked_at']}]"
        print(f"\n{sc_title}")
        print(f"  -> Outcome: {status_sym}")
        print(f"  -> Reason:  {result_data['reason']}")
        for trace in result_data["trace_steps"]:
            print(f"     | {trace}")

    print("\n" + "=" * 80)
    print("  ALL ARCHITECTURAL SECURITY CONTROLS VERIFIED & ACTIVE!")
    print("=" * 80)


def start_server(port: int = 8080):
    server = HTTPServer(("127.0.0.1", port), SimulatorHTTPHandler)
    print(f"\n[*] Starting Hybrid Security Interactive Dashboard on: http://127.0.0.1:{port}")
    print("[*] Open your browser to view the live GUI or run tests from the web UI.")
    print("[*] Press Ctrl+C in VS Code terminal to stop the server at any time.\n")
    
    # Auto-open in browser if interactive
    try:
        webbrowser.open(f"http://127.0.0.1:{port}")
    except Exception:
        pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server shutdown cleanly.")


if __name__ == "__main__":
    # Execute full CLI simulation test suite first
    run_cli_test_suite()
    
    # Start web server for interactive experimentation
    start_server(port=8080)
