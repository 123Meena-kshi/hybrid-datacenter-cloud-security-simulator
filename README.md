# Hybrid Datacenter & Cloud Security Architecture Simulator

## Cisco Cybersecurity Virtual Internship – Industry Task

A cybersecurity simulation project that demonstrates how a modern enterprise can protect applications, users, workloads, databases, and cloud infrastructure using a **Zero-Trust and Defense-in-Depth security architecture**.

The project models a hybrid environment consisting of a private datacenter, cloud workloads, Kubernetes services, databases, remote users, and external attackers.

---

## 🚀 Project Overview

Modern organizations operate across campus networks, private datacenters, and cloud environments. This creates multiple security challenges such as:

- Unauthorized access
- Compromised user devices
- Lateral movement
- Direct database attacks
- Malicious container deployment
- Container runtime attacks
- Data exfiltration
- Command-and-control communication
- Insecure cloud-to-datacenter communication

This project provides an interactive simulator to demonstrate how multiple security controls work together to detect, block, and isolate these threats.

---

## 🎯 Objectives

The main objectives of this project are:

1. Implement Zero-Trust access control.
2. Simulate Identity and Access Management (IAM).
3. Verify device posture before granting access.
4. Simulate Multi-Factor Authentication.
5. Implement short-lived ephemeral credentials.
6. Simulate Transit Gateway routing.
7. Demonstrate centralized firewall inspection.
8. Implement Security Group-based segmentation.
9. Demonstrate Kubernetes micro-segmentation.
10. Simulate container admission security.
11. Detect runtime container anomalies.
12. Prevent database bypass attacks.
13. Detect malicious data exfiltration.
14. Maintain security audit logs.
15. Provide an interactive security operations dashboard.

---

## 🏗️ Architecture

```text
                    ┌──────────────────────┐
                    │ Remote Users / Campus│
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │       IAM / ZTNA     │
                    │ MFA + RBAC + Posture │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Transit Gateway      │
                    │ Hub-and-Spoke Routing │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Central NGFW / IDS    │
                    │ Deep Packet Inspection│
                    └──────────┬───────────┘
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
        ┌─────────────────┐         ┌─────────────────┐
        │ LMS Cloud Spoke │         │ Research Spoke  │
        │ Kubernetes/EKS  │         │ Kubernetes/EKS  │
        └────────┬────────┘         └────────┬────────┘
                 │                           │
                 ▼                           ▼
        ┌─────────────────┐         ┌─────────────────┐
        │ Private Database│         │ Research DB    │
        └─────────────────┘         └─────────────────┘
                 │
                 ▼
        ┌─────────────────────────┐
        │ Private Datacenter      │
        │ OpenShift / SIS Database│
        └─────────────────────────┘
