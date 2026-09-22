"""Seed realistic threat and business service data for a given organisation.

Seeds threats across all four statuses (detected, in-progress, kept-safe,
accepted) so every section of the Decision Workbench is populated.

Usage:
    poetry run python scripts/seed_threats.py              # seeds org_id=4 (Risklence)
    poetry run python scripts/seed_threats.py --org-id 2  # seeds a specific org
    poetry run python scripts/seed_threats.py --clear     # wipe existing then re-seed
"""

import argparse
import uuid
from datetime import datetime, timezone

from src.core.database import get_db_context
from src.core.models import BusinessService, Threat


# ─── THREAT SEED DATA ─────────────────────────────────────────────────────────

THREATS = [
    # ── DETECTED (requires a decision) ────────────────────────────────────────
    {
        "status": "detected",
        "severity": "critical",
        "source": "glic",
        "asset": "POS WiFi Network",
        "tier": "Mission Critical",
        "signal": "Rogue access point detected on trading floor SSID — MAC address not in approved device registry",
        "what_it_means": "An unauthorised device is broadcasting on your payment network. If a customer or attacker connects, card data can be intercepted in real time.",
        "recommendation": "Isolate the rogue AP immediately via your NAC controller, identify the physical device, and file a PCI-DSS incident report within 24 hours.",
        "intelligence": {
            "recommendedAction": "escalated",
            "confidence": 94,
            "basis": "PCI-DSS 4.0 §11.2.2 + peer signal pattern (3 similar incidents in retail sector last 30 days)",
            "reasoning": "Rogue AP on a cardholder data environment network is a mandatory escalation under PCI-DSS. Delay increases regulatory exposure.",
            "peerData": "3 of 11 peer organisations reported identical MAC spoofing pattern last month; all escalated within 2 hours.",
            "frameworkGuidance": "PCI-DSS 4.0 requires rogue AP detection and response. NIS2 Art. 21 requires incident notification within 24h.",
            "alternativeNote": "Accepting this risk is not permissible under PCI-DSS scope.",
        },
        "daily_cost": 18400,
        "frameworks": ["PCI-DSS", "NIS2"],
        "requires_escalation": True,
    },
    {
        "status": "detected",
        "severity": "high",
        "source": "splunk",
        "asset": "Core Banking API",
        "tier": "Mission Critical",
        "signal": "Spike in 401 errors from IP range 185.220.x.x — 847 failed auth attempts in 4 minutes",
        "what_it_means": "A credential-stuffing attack is targeting your banking API. Accounts with reused passwords are at high risk of takeover.",
        "recommendation": "Trigger adaptive MFA for all affected accounts, temporarily rate-limit the IP range, and notify affected users to change passwords.",
        "intelligence": {
            "recommendedAction": "jira",
            "confidence": 88,
            "basis": "Tor exit node IP range + credential stuffing signature from Splunk threat intel feed",
            "reasoning": "Rate of attempts (847 in 4 min) exceeds brute-force thresholds. IP range is a known Tor exit node cluster used in financial fraud campaigns.",
            "peerData": "5 peer banks saw identical pattern over the past 7 days; 2 suffered account takeovers before responding.",
            "frameworkGuidance": "FCA SYSC 13.7 requires adequate controls against unauthorised access. DORA Art. 17 mandates incident classification.",
            "alternativeNote": None,
        },
        "daily_cost": 9200,
        "frameworks": ["FCA", "DORA", "NIS2"],
        "requires_escalation": False,
    },
    {
        "status": "detected",
        "severity": "high",
        "source": "cmdb",
        "asset": "AWS Production (eu-west-1)",
        "tier": "Business Critical",
        "signal": "S3 bucket 'risklence-customer-exports' ACL changed to public-read at 03:14 UTC",
        "what_it_means": "Customer export files are publicly accessible on the internet. Any data written to this bucket since 03:14 is exposed.",
        "recommendation": "Revoke public ACL immediately, audit access logs for downloads since 03:14, and notify your DPO within 72 hours if PII was exposed.",
        "intelligence": {
            "recommendedAction": "jira",
            "confidence": 97,
            "basis": "CloudTrail ACL change event + CMDB bucket classification: PII",
            "reasoning": "Bucket is classified as containing PII. Public ACL change outside business hours is a high-confidence data exposure event.",
            "peerData": "Misconfigured S3 buckets account for 31% of GDPR breach notifications in FS sector (ICO 2024).",
            "frameworkGuidance": "GDPR Art. 33 requires breach notification to ICO within 72 hours. ISO 22301 §8.4 requires data exposure response procedure.",
            "alternativeNote": None,
        },
        "daily_cost": 12800,
        "frameworks": ["GDPR", "ISO22301"],
        "requires_escalation": True,
    },
    {
        "status": "detected",
        "severity": "medium",
        "source": "glic",
        "asset": "Primary Database (PostgreSQL)",
        "tier": "Mission Critical",
        "signal": "Database user 'reports_svc' executed 14 schema-level DDL commands outside deployment window",
        "what_it_means": "A service account made structural database changes without going through your change management process. This could be a compromised account or an uncontrolled deployment.",
        "recommendation": "Audit the DDL commands executed, verify with the engineering team whether this was intentional, and rotate the service account credentials.",
        "intelligence": {
            "recommendedAction": "servicenow",
            "confidence": 76,
            "basis": "DDL outside change window + service account (not human) actor",
            "reasoning": "Service accounts should not perform DDL. Either the account is compromised or change management controls are being bypassed.",
            "peerData": "Insider threat via service account credentials is the 2nd most common database breach vector (Verizon DBIR 2024).",
            "frameworkGuidance": "ISO 22301 §8.3 requires change management controls. DORA Art. 9 requires access control monitoring.",
            "alternativeNote": "If intentional, raise a change record retroactively and review the change management process.",
        },
        "daily_cost": 3600,
        "frameworks": ["ISO22301", "DORA"],
        "requires_escalation": False,
    },

    # ── IN-PROGRESS (decision made, mitigation underway) ──────────────────────
    {
        "status": "in-progress",
        "severity": "high",
        "source": "splunk",
        "asset": "API Gateway (Kong)",
        "tier": "Business Critical",
        "signal": "JWT tokens issued without expiry claim — 2,341 long-lived tokens active in production",
        "what_it_means": "Sessions never expire, so any stolen token provides permanent access. This is a critical authentication design flaw.",
        "recommendation": "Deploy token expiry patch, force rotation of all active tokens, and implement refresh token pattern.",
        "intelligence": {
            "recommendedAction": "jira",
            "confidence": 91,
            "basis": "OWASP API Security Top 10 — Broken Authentication + SAST finding",
            "reasoning": "Long-lived tokens dramatically increase the blast radius of any token theft. Patch is low-risk and high-impact.",
            "peerData": "2 peer FinTechs reported token theft exploits leveraging non-expiring JWTs in Q1 2025.",
            "frameworkGuidance": "FCA SYSC 13.7 requires session management controls. NIS2 Art. 21 mandates authentication best practices.",
            "alternativeNote": None,
        },
        "daily_cost": 7400,
        "frameworks": ["FCA", "NIS2"],
        "requires_escalation": False,
        "decision": {
            "action": "jira",
            "by": "admin@risklence.com",
            "role": "admin",
            "rationale": "Raised JR-2847 to patch token expiry. Engineering team picked it up — ETA 2 days.",
            "ref": "JR-2847",
            "timestamp": "2026-03-20 09:14",
            "reviewDate": "2026-03-24",
        },
    },
    {
        "status": "in-progress",
        "severity": "medium",
        "source": "cross-org",
        "asset": "Corporate Endpoint Fleet",
        "tier": "Business Critical",
        "signal": "Cross-org pattern: 4 peer organisations detected phishing campaign targeting CFO role — same lure template observed",
        "what_it_means": "A coordinated spear-phishing campaign is targeting finance leadership across your sector. Your CFO and finance team are likely on the target list.",
        "recommendation": "Issue a targeted security awareness alert to finance leadership, enable enhanced email filtering for CFO inbox, and review recent wire transfer approvals.",
        "intelligence": {
            "recommendedAction": "servicenow",
            "confidence": 82,
            "basis": "Cross-org threat intelligence — 4 confirmed peer incidents with identical lure template",
            "reasoning": "Sector-wide campaign with identical template suggests automated targeting. Finance leadership is highest value target.",
            "peerData": "4 peer organisations confirmed campaign. 1 reported successful BEC (Business Email Compromise) resulting in £240k wire fraud.",
            "frameworkGuidance": "FCA requires firms to manage operational risks from social engineering. DORA Art. 13 mandates threat intelligence sharing.",
            "alternativeNote": None,
        },
        "daily_cost": 4800,
        "frameworks": ["FCA", "DORA"],
        "requires_escalation": False,
        "decision": {
            "action": "servicenow",
            "by": "admin@risklence.com",
            "role": "admin",
            "rationale": "Created CHG0034521 to push enhanced email filtering rules and issue awareness comms to finance team.",
            "ref": "CHG0034521",
            "timestamp": "2026-03-21 14:32",
            "reviewDate": "2026-03-28",
        },
    },

    # ── KEPT SAFE (fully resolved) ─────────────────────────────────────────────
    {
        "status": "kept-safe",
        "severity": "critical",
        "source": "glic",
        "asset": "Core Router (Cisco)",
        "tier": "Mission Critical",
        "signal": "CVE-2025-20188 — unauthenticated remote code execution in IOS XE management interface — CVSS 10.0",
        "what_it_means": "An unpatched critical vulnerability allowed remote code execution on your core routing infrastructure with no authentication required.",
        "recommendation": "Apply Cisco security advisory patch immediately. Disable web UI on management interface if patch cannot be applied within 24h.",
        "intelligence": {
            "recommendedAction": "jira",
            "confidence": 99,
            "basis": "Cisco PSIRT advisory + active exploitation confirmed in the wild",
            "reasoning": "CVSS 10.0 with active exploitation. No authentication bypass required. Patch is available and must be applied immediately.",
            "peerData": "CISA KEV catalogue entry added. 23% of organisations in sector confirmed patched within 48h of advisory.",
            "frameworkGuidance": "NIS2 Art. 21 requires patching of critical vulnerabilities. DORA Art. 9 mandates vulnerability management programme.",
            "alternativeNote": None,
        },
        "daily_cost": 22000,
        "frameworks": ["NIS2", "DORA", "ISO22301"],
        "requires_escalation": True,
        "decision": {
            "action": "jira",
            "by": "admin@risklence.com",
            "role": "admin",
            "rationale": "Emergency patch applied to all Cisco IOS XE devices via JR-2801. Web UI disabled on management interface as interim control.",
            "ref": "JR-2801",
            "timestamp": "2026-03-15 07:43",
            "reviewDate": None,
            "outcome": "Patch applied to 8 devices. Vulnerability scanner confirms remediated. No evidence of prior exploitation in logs.",
            "outcomeQuality": "fully-resolved",
        },
        "saved_per_hour": 916,
        "resolved_on": "17 Mar 2026",
    },
    {
        "status": "kept-safe",
        "severity": "high",
        "source": "splunk",
        "asset": "Web Server (NGINX)",
        "tier": "Business Critical",
        "signal": "TLS 1.0 and 1.1 still negotiated on customer-facing endpoints — 12% of connections using deprecated protocol",
        "what_it_means": "Deprecated TLS versions are vulnerable to POODLE and BEAST attacks. Customer connections using these versions can be decrypted by an active network attacker.",
        "recommendation": "Disable TLS 1.0 and 1.1 in NGINX config. Enforce TLS 1.2 minimum, TLS 1.3 preferred.",
        "intelligence": {
            "recommendedAction": "jira",
            "confidence": 95,
            "basis": "PCI-DSS 4.0 §4.2.1 — TLS 1.0/1.1 not permitted in cardholder data environments after March 2025",
            "reasoning": "PCI-DSS compliance deadline has passed. Continued use is a direct compliance violation and an active vulnerability.",
            "peerData": "Industry average TLS 1.2+ adoption is 97%. Remaining 3% are predominantly legacy mobile clients.",
            "frameworkGuidance": "PCI-DSS 4.0 §4.2.1 mandates TLS 1.2+. FCA expects encryption best practices.",
            "alternativeNote": None,
        },
        "daily_cost": 5600,
        "frameworks": ["PCI-DSS", "FCA"],
        "requires_escalation": False,
        "decision": {
            "action": "jira",
            "by": "admin@risklence.com",
            "role": "admin",
            "rationale": "JR-2789 deployed NGINX config update disabling TLS 1.0/1.1 across all customer-facing endpoints.",
            "ref": "JR-2789",
            "timestamp": "2026-03-10 11:20",
            "reviewDate": None,
            "outcome": "TLS scan confirms 100% of connections now using TLS 1.2+. Zero customer complaints reported.",
            "outcomeQuality": "fully-resolved",
        },
        "saved_per_hour": 233,
        "resolved_on": "12 Mar 2026",
    },

    # ── ACCEPTED (risk accepted, no mitigation) ────────────────────────────────
    {
        "status": "accepted",
        "severity": "low",
        "source": "cmdb",
        "asset": "Analytics DB (Snowflake)",
        "tier": "Business Critical",
        "signal": "Snowflake instance accessible from any IP — no IP allowlist configured",
        "what_it_means": "Your analytics database can be reached from any internet IP. Combined with a compromised credential, this enables direct data exfiltration.",
        "recommendation": "Restrict Snowflake network policy to office IP ranges and known CI/CD runner IPs.",
        "intelligence": {
            "recommendedAction": "accepted",
            "confidence": 61,
            "basis": "CIS Snowflake Benchmark + CMDB network classification",
            "reasoning": "Analytics DB contains aggregated non-PII data. Risk is lower than production DBs but allowlisting is a low-effort improvement.",
            "peerData": "44% of peer organisations have implemented Snowflake IP allowlisting. Most cited ease of implementation.",
            "frameworkGuidance": "ISO 22301 §8.3 recommends network access controls. Not a mandatory control for non-PII analytics data.",
            "alternativeNote": "Accepted risk is reasonable given non-PII data classification and Snowflake's MFA enforcement.",
        },
        "daily_cost": 1200,
        "frameworks": ["ISO22301"],
        "requires_escalation": False,
        "decision": {
            "action": "accepted",
            "by": "admin@risklence.com",
            "role": "admin",
            "rationale": "Analytics DB contains only aggregated, anonymised data. MFA is enforced on all Snowflake accounts. Risk is within appetite. Will revisit at next architecture review.",
            "ref": None,
            "timestamp": "2026-03-18 16:05",
            "reviewDate": "2026-06-18",
        },
    },
]


# ─── SERVICE SEED DATA ────────────────────────────────────────────────────────

SERVICES = [
    {
        "name": "Card Processing",
        "tier": "Mission Critical",
        "trading_impact": "Direct impact on revenue — card payment failure causes immediate transaction loss and regulatory exposure under PCI-DSS.",
        "l1": [],  # populated after assets are looked up
        "l2": [],
        "l3": [],
        "_l1_names": ["POS WiFi Network", "Core Banking API"],
        "_l2_names": ["API Gateway (Kong)", "Primary Database (PostgreSQL)"],
        "_l3_names": ["AWS Production (eu-west-1)", "Web Server (NGINX)"],
    },
    {
        "name": "Customer Portal",
        "tier": "Business Critical",
        "trading_impact": "Customer self-service unavailability increases call centre load and risks SLA breach. Prolonged outage triggers FCA operational resilience review.",
        "l1": [],
        "l2": [],
        "l3": [],
        "_l1_names": ["Core Banking API", "Web Server (NGINX)"],
        "_l2_names": ["API Gateway (Kong)", "AWS Production (eu-west-1)"],
        "_l3_names": ["Analytics DB (Snowflake)", "Primary Database (PostgreSQL)"],
    },
]


# ─── SEED FUNCTIONS ───────────────────────────────────────────────────────────

def seed_threats(db, org_id: int) -> list[Threat]:
    now = datetime.now(timezone.utc)
    created = []
    for t in THREATS:
        threat = Threat(
            id=str(uuid.uuid4()),
            organization_id=org_id,
            status=t["status"],
            severity=t["severity"],
            source=t["source"],
            asset=t["asset"],
            tier=t["tier"],
            signal=t["signal"],
            what_it_means=t["what_it_means"],
            recommendation=t["recommendation"],
            intelligence=t["intelligence"],
            daily_cost=t["daily_cost"],
            frameworks=t["frameworks"],
            requires_escalation=t["requires_escalation"],
            decision=t.get("decision"),
            saved_per_hour=t.get("saved_per_hour"),
            resolved_on=t.get("resolved_on"),
            created_at=now,
            updated_at=now,
        )
        db.add(threat)
        created.append(threat)
    db.flush()
    return created


def seed_services(db, org_id: int, threats: list[Threat]) -> None:
    now = datetime.now(timezone.utc)
    # Build a name→id lookup from the threats we just inserted
    asset_ids: dict[str, str] = {t.asset: t.id for t in threats}

    for s in SERVICES:
        service = BusinessService(
            id=str(uuid.uuid4()),
            organization_id=org_id,
            name=s["name"],
            tier=s["tier"],
            trading_impact=s["trading_impact"],
            l1=[asset_ids[n] for n in s["_l1_names"] if n in asset_ids],
            l2=[asset_ids[n] for n in s["_l2_names"] if n in asset_ids],
            l3=[asset_ids[n] for n in s["_l3_names"] if n in asset_ids],
            created_at=now,
            updated_at=now,
        )
        db.add(service)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed threat and service data")
    parser.add_argument("--org-id", type=int, default=4, help="Organisation ID to seed (default: 4 = Risklence)")
    parser.add_argument("--clear", action="store_true", help="Delete existing threats and services before seeding")
    args = parser.parse_args()

    with get_db_context() as db:
        if args.clear:
            deleted_t = db.query(Threat).filter(Threat.organization_id == args.org_id).delete()
            deleted_s = db.query(BusinessService).filter(BusinessService.organization_id == args.org_id).delete()
            print(f"Cleared {deleted_t} threats and {deleted_s} services for org {args.org_id}")

        threats = seed_threats(db, args.org_id)
        seed_services(db, args.org_id, threats)
        db.commit()

        counts = {}
        for t in threats:
            counts[t.status] = counts.get(t.status, 0) + 1

        print(f"\nSeeded {len(threats)} threats for org {args.org_id}:")
        for status, count in sorted(counts.items()):
            print(f"  {status}: {count}")
        print(f"Seeded {len(SERVICES)} business services")
        print("\nDone — refresh the dashboard to see live data.")


if __name__ == "__main__":
    main()
