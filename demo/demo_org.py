#!/usr/bin/env python3
"""
Demo data generator — Midwest Family Health Partners.

Creates a realistic mid-size multi-location healthcare practice in Missouri
with 8 vendors spanning the full risk spectrum: from well-established EHR
providers (LOW) to shadow AI usage (CRITICAL).

VerifAI Security | Created by Nathan Mills
"""

import os
import random
import sys
import tempfile
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Ensure project root is importable
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from vrm.models import (
    Answer,
    AssessmentResponse,
    AssessmentType,
    BAA,
    BAAStatus,
    DataVolume,
    Vendor,
    VendorStatus,
    VendorTier,
    VendorType,
    Verification,
    VerificationStatus,
    VerificationType,
)
from vrm.db import VendorDatabase
from vrm.controls import get_questions_for_vendor, CONTROL_INDEX
from vrm.risk_engine import run_assessment

# Colorama (graceful fallback)
try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class _FakeColor:
        def __getattr__(self, name):
            return ""

    Fore = _FakeColor()
    Back = _FakeColor()
    Style = _FakeColor()


# ============================================================================
# Constants
# ============================================================================

ORG_NAME = "Midwest Family Health Partners"
ORG_LOCATION = "Jefferson City, Missouri"
ORG_DESCRIPTION = (
    "A mid-size multi-location family medicine practice with 12 physicians, "
    "3 nurse practitioners, and 45 support staff across 4 clinic locations. "
    "Annual patient volume: ~28,000 unique patients."
)

# Reproducible randomness
SEED = 42


# ============================================================================
# Response generation helpers
# ============================================================================

def _generate_responses(
    questions,
    target_score: float,
    rng: random.Random,
    *,
    force_no_ids: Optional[List[str]] = None,
    force_partial_ids: Optional[List[str]] = None,
    force_unknown_ids: Optional[List[str]] = None,
    force_na_ids: Optional[List[str]] = None,
) -> Dict[str, AssessmentResponse]:
    """
    Generate assessment responses that approximate a target overall score.

    Strategy:
        - Assign forced answers first.
        - For high-target vendors (>75), protect critical questions (always YES)
          and only put PARTIAL on low-weight non-critical questions.
        - For low-target vendors (<30), aggressively fail including criticals.
        - For mid-range, spread deficiencies across non-critical questions first.

    The scoring system uses weighted penalties:
        YES=0.0, PARTIAL=0.4, NO=1.0, UNKNOWN=0.7, NA=excluded.
    So score ≈ 100 * (1 - weighted_penalty / total_weight).
    """
    force_no = set(force_no_ids or [])
    force_partial = set(force_partial_ids or [])
    force_unknown = set(force_unknown_ids or [])
    force_na = set(force_na_ids or [])

    # Build list of (question, forced_answer_or_None)
    items = []
    for q in questions:
        if q.id in force_no:
            items.append((q, Answer.NO))
        elif q.id in force_partial:
            items.append((q, Answer.PARTIAL))
        elif q.id in force_unknown:
            items.append((q, Answer.UNKNOWN))
        elif q.id in force_na:
            items.append((q, Answer.NOT_APPLICABLE))
        else:
            items.append((q, None))

    # Calculate current penalty from forced answers
    total_weight = sum(q.weight for q, a in items if a != Answer.NOT_APPLICABLE)
    forced_penalty = 0.0
    free_items = []

    for q, a in items:
        if a == Answer.NOT_APPLICABLE:
            continue
        if a == Answer.YES:
            pass  # penalty 0
        elif a == Answer.NO:
            forced_penalty += q.weight * 1.0
        elif a == Answer.PARTIAL:
            forced_penalty += q.weight * 0.4
        elif a == Answer.UNKNOWN:
            forced_penalty += q.weight * 0.7
        elif a is None:
            free_items.append(q)

    # Target penalty: score = 100 * (1 - penalty/total_weight)
    # penalty = total_weight * (1 - score/100)
    target_penalty = total_weight * (1.0 - target_score / 100.0)
    remaining_penalty = max(0.0, target_penalty - forced_penalty)

    # For high-score vendors (>= 75), sort so critical/high-weight questions
    # come LAST (get YES), and non-critical light questions come first (get deficiencies).
    # For low-score vendors (< 30), put critical questions first to fail them.
    # For mid-range, shuffle then sort by weight ascending.
    rng.shuffle(free_items)

    if target_score >= 60:
        # Protect critical questions: sort so non-critical low-weight come first
        free_items.sort(key=lambda q: (q.is_critical, q.weight))
    elif target_score < 30:
        # Fail critical questions first for maximum damage
        free_items.sort(key=lambda q: (-q.is_critical, -q.weight))
    else:
        # Mid-range (30-59): non-critical first, then by weight ascending
        free_items.sort(key=lambda q: (q.is_critical, q.weight))

    remaining_weight = sum(q.weight for q in free_items)
    assignments: Dict[str, Answer] = {}

    for q in free_items:
        if remaining_weight <= 0:
            assignments[q.id] = Answer.YES
            continue

        # Decide answer based on remaining penalty budget
        fraction = remaining_penalty / remaining_weight if remaining_weight > 0 else 0

        # Protection levels for critical questions based on target score:
        #   >= 80: always YES on critical (no findings from critical Qs)
        #   60-79: downgrade NO→PARTIAL on critical (findings but not CRITICAL severity)
        #   < 60: no protection (critical Qs can get NO = CRITICAL findings)
        hard_protect = target_score >= 80 and q.is_critical
        soft_protect = 60 <= target_score < 80 and q.is_critical

        if fraction >= 0.85:
            # Need most questions to fail
            roll = rng.random()
            if hard_protect:
                ans = Answer.PARTIAL
                penalty = q.weight * 0.4
            elif soft_protect:
                # Allow PARTIAL/UNKNOWN but not NO
                if roll < 0.50:
                    ans = Answer.PARTIAL
                    penalty = q.weight * 0.4
                else:
                    ans = Answer.UNKNOWN
                    penalty = q.weight * 0.7
            elif roll < 0.70:
                ans = Answer.NO
                penalty = q.weight * 1.0
            elif roll < 0.90:
                ans = Answer.UNKNOWN
                penalty = q.weight * 0.7
            else:
                ans = Answer.PARTIAL
                penalty = q.weight * 0.4
        elif fraction >= 0.55:
            roll = rng.random()
            if hard_protect:
                if roll < 0.10:
                    ans = Answer.PARTIAL
                    penalty = q.weight * 0.4
                else:
                    ans = Answer.YES
                    penalty = 0.0
            elif soft_protect:
                if roll < 0.30:
                    ans = Answer.PARTIAL
                    penalty = q.weight * 0.4
                elif roll < 0.45:
                    ans = Answer.UNKNOWN
                    penalty = q.weight * 0.7
                else:
                    ans = Answer.YES
                    penalty = 0.0
            elif roll < 0.35:
                ans = Answer.NO
                penalty = q.weight * 1.0
            elif roll < 0.55:
                ans = Answer.UNKNOWN
                penalty = q.weight * 0.7
            elif roll < 0.75:
                ans = Answer.PARTIAL
                penalty = q.weight * 0.4
            else:
                ans = Answer.YES
                penalty = 0.0
        elif fraction >= 0.30:
            roll = rng.random()
            if hard_protect:
                ans = Answer.YES
                penalty = 0.0
            elif soft_protect:
                if roll < 0.15:
                    ans = Answer.PARTIAL
                    penalty = q.weight * 0.4
                else:
                    ans = Answer.YES
                    penalty = 0.0
            elif roll < 0.15:
                ans = Answer.NO
                penalty = q.weight * 1.0
            elif roll < 0.30:
                ans = Answer.UNKNOWN
                penalty = q.weight * 0.7
            elif roll < 0.50:
                ans = Answer.PARTIAL
                penalty = q.weight * 0.4
            else:
                ans = Answer.YES
                penalty = 0.0
        elif fraction >= 0.10:
            roll = rng.random()
            if hard_protect or soft_protect:
                ans = Answer.YES
                penalty = 0.0
            elif roll < 0.05:
                ans = Answer.NO
                penalty = q.weight * 1.0
            elif roll < 0.15:
                ans = Answer.PARTIAL
                penalty = q.weight * 0.4
            else:
                ans = Answer.YES
                penalty = 0.0
        else:
            # Near-perfect — almost all YES
            roll = rng.random()
            if roll < 0.03 and not q.is_critical:
                ans = Answer.PARTIAL
                penalty = q.weight * 0.4
            else:
                ans = Answer.YES
                penalty = 0.0

        assignments[q.id] = ans
        remaining_penalty = max(0.0, remaining_penalty - penalty)
        remaining_weight -= q.weight

    # Build final response dict
    responses: Dict[str, AssessmentResponse] = {}
    assessed_time = datetime.now() - timedelta(hours=rng.randint(1, 48))

    for q, forced in items:
        answer = forced if forced is not None else assignments.get(q.id, Answer.YES)
        responses[q.id] = AssessmentResponse(
            question_id=q.id,
            answer=answer,
            evidence_provided=answer == Answer.YES,
            evidence_description=(
                f"Evidence provided for {q.subdomain}" if answer == Answer.YES else ""
            ),
            assessed_date=assessed_time,
        )

    return responses


# ============================================================================
# Vendor definitions
# ============================================================================

def _build_vendors(rng: random.Random) -> List[dict]:
    """Return configuration dicts for all 8 demo vendors."""
    return [
        # 1. Epic Systems — EHR Provider (LOW risk, ~92/100)
        {
            "name": "Epic Systems",
            "legal_name": "Epic Systems Corporation",
            "vendor_type": VendorType.EHR_PROVIDER,
            "phi_access": True,
            "phi_types": [
                "demographics", "diagnoses", "medications", "lab_results",
                "imaging", "billing", "insurance",
            ],
            "data_volume": DataVolume.HIGH,
            "integration_type": ["HL7", "FHIR", "API"],
            "contact_name": "Sarah Chen",
            "contact_email": "schen@epic.com",
            "contact_phone": "(608) 271-9000",
            "target_score": 92,
            "baa": {
                "status": BAAStatus.ACTIVE,
                "effective_date": date(2024, 3, 1),
                "expiration_date": date(2027, 2, 28),
                "breach_notification_hours": 24,
                "contingency_notification_hours": 24,
                "subcontractor_flow_down": True,
                "auto_renewal": True,
                "signed_by_vendor": "Judy Faulkner",
                "signed_by_org": "Dr. Patricia Whitfield",
            },
            "verification_status": VerificationStatus.VERIFIED,
            "verification_completed": date(2025, 11, 15),
            "onboarded_date": date(2022, 6, 1),
            "notes": [
                "Primary EHR platform — enterprise deployment across all 4 locations",
                "SOC 2 Type II and HITRUST certified",
            ],
        },
        # 2. CloudMD Telehealth — Telehealth Provider (MEDIUM risk, ~68/100)
        {
            "name": "CloudMD Telehealth",
            "legal_name": "CloudMD Health Technologies Inc.",
            "vendor_type": VendorType.TELEHEALTH,
            "phi_access": True,
            "phi_types": ["demographics", "diagnoses", "medications"],
            "data_volume": DataVolume.MEDIUM,
            "integration_type": ["FHIR", "API", "WEB_PORTAL"],
            "contact_name": "Michael Torres",
            "contact_email": "m.torres@cloudmd-telehealth.com",
            "contact_phone": "(415) 555-0192",
            "target_score": 68,
            # Encryption gaps: PARTIAL on critical, NO on non-critical → push domains < 40
            "force_partial": ["EN-01", "EN-02", "EN-03", "EN-08", "EN-09", "EN-11", "EN-14"],  # Critical encryption → PARTIAL
            "force_no": ["EN-04", "EN-05", "EN-06", "EN-07", "EN-10", "EN-12", "EN-13", "EN-15",  # All non-critical encryption → NO
                         "NS-03", "NS-06", "NS-07", "NS-08", "NS-10"],  # Non-critical network → NO
            "force_unknown": ["NS-01", "NS-02", "NS-04", "NS-05", "NS-09"],  # Critical network → UNKNOWN (HIGH findings, not CRITICAL)
            "baa": {
                "status": BAAStatus.ACTIVE,
                "effective_date": date(2024, 9, 1),
                "expiration_date": date(2026, 8, 31),
                "breach_notification_hours": 72,  # Non-compliant
                "contingency_notification_hours": 72,  # Non-compliant
                "subcontractor_flow_down": True,
                "auto_renewal": False,
                "signed_by_vendor": "James Liu",
                "signed_by_org": "Dr. Patricia Whitfield",
            },
            "verification_status": VerificationStatus.PENDING,
            "verification_due": date(2026, 5, 15),
            "onboarded_date": date(2024, 9, 1),
            "notes": [
                "Video telehealth platform — adopted during COVID expansion",
                "Breach notification terms need amendment to 24 hours",
            ],
        },
        # 3. MedBill Pro — Billing Service (HIGH risk, ~45/100)
        {
            "name": "MedBill Pro",
            "legal_name": "MedBill Pro LLC",
            "vendor_type": VendorType.BILLING_SERVICE,
            "phi_access": True,
            "phi_types": ["billing", "insurance", "demographics"],
            "data_volume": DataVolume.HIGH,
            "integration_type": ["SFTP", "API"],
            "contact_name": "Karen Williams",
            "contact_email": "kwilliams@medbillpro.com",
            "contact_phone": "(314) 555-0847",
            "target_score": 45,
            "force_no": ["AC-02", "AC-04", "AM-01"],  # No MFA, shared creds, no audit
            "baa": {
                "status": BAAStatus.RENEWAL_PENDING,
                "effective_date": date(2023, 7, 1),
                "expiration_date": date(2026, 5, 22),  # ~45 days from now
                "breach_notification_hours": 48,
                "contingency_notification_hours": 72,
                "subcontractor_flow_down": False,
                "auto_renewal": False,
                "signed_by_vendor": "Robert Patel",
                "signed_by_org": "Dr. Patricia Whitfield",
            },
            "verification_status": VerificationStatus.FAILED,
            "verification_completed": date(2026, 2, 10),
            "onboarded_date": date(2023, 7, 1),
            "notes": [
                "Third-party billing — handles all claims for 4 locations",
                "CRITICAL: Multiple security deficiencies identified in last assessment",
                "Corrective action plan requested — due April 30, 2026",
            ],
        },
        # 4. SecureRx Pharmacy — Pharmacy System (MEDIUM risk, ~71/100)
        {
            "name": "SecureRx Pharmacy Network",
            "legal_name": "SecureRx Inc.",
            "vendor_type": VendorType.PHARMACY_SYSTEM,
            "phi_access": True,
            "phi_types": ["medications", "demographics"],
            "data_volume": DataVolume.MEDIUM,
            "integration_type": ["HL7", "SFTP"],
            "contact_name": "David Park",
            "contact_email": "dpark@securerx.com",
            "contact_phone": "(816) 555-0331",
            "target_score": 71,
            # IR/BC gaps: UNKNOWN on critical (HIGH findings), NO on non-critical (MEDIUM findings)
            "force_unknown": ["IR-01", "IR-02", "IR-03", "IR-05", "IR-07", "IR-10", "IR-12", "IR-14", "IR-15",  # Critical IR → UNKNOWN
                              "BC-01", "BC-02", "BC-03", "BC-05", "BC-06", "BC-07"],  # Critical BC → UNKNOWN
            "force_no": ["IR-04", "IR-06", "IR-08", "IR-09", "IR-11", "IR-13",  # Non-critical IR → NO
                         "BC-04", "BC-08", "BC-09", "BC-10"],  # Non-critical BC → NO
            "baa": {
                "status": BAAStatus.ACTIVE,
                "effective_date": date(2025, 1, 15),
                "expiration_date": date(2027, 1, 14),
                "breach_notification_hours": 24,
                "contingency_notification_hours": 24,
                "subcontractor_flow_down": True,
                "auto_renewal": True,
                "signed_by_vendor": "Lisa Chang",
                "signed_by_org": "Dr. Patricia Whitfield",
            },
            "verification_status": VerificationStatus.VERIFIED,
            "verification_completed": date(2025, 10, 20),
            "onboarded_date": date(2023, 1, 15),
            "notes": [
                "E-prescribing and medication management integration",
                "Incident response plan needs updating — requested remediation by Q2 2026",
            ],
        },
        # 5. ChatGPT (Shadow AI) — CRITICAL risk (~12/100)
        {
            "name": "ChatGPT (Shadow AI Usage)",
            "legal_name": "OpenAI Inc.",
            "dba_name": "ChatGPT",
            "vendor_type": VendorType.OTHER,
            "phi_access": True,
            "phi_types": ["demographics", "diagnoses", "medications"],
            "data_volume": DataVolume.MEDIUM,
            "integration_type": ["WEB_PORTAL"],
            "contact_name": "N/A — Consumer product",
            "contact_email": "",
            "contact_phone": "",
            "target_score": 12,
            "force_no": [
                "AC-01", "AC-02", "AC-03", "AC-04", "AC-05",
                "EP-01", "EP-02", "EP-03",
                "AM-01", "AM-02",
                "IR-01", "IR-02",
                "VS-01", "VS-02", "VS-03",
                "NS-01", "NS-02", "NS-03",
            ],
            "force_unknown": [
                "EP-04", "EP-05", "AM-03", "AM-04",
                "BC-01", "BC-02", "BC-03",
                "WS-01", "WS-02",
            ],
            "baa": None,  # No BAA possible
            "verification_status": None,  # Cannot verify
            "onboarded_date": date(2025, 8, 1),
            "notes": [
                "CRITICAL: Discovered staff using ChatGPT with patient data",
                "No BAA available — OpenAI does not sign BAAs for consumer ChatGPT",
                "PHI exposed to model training — potential breach notification required",
                "Immediate action: block access and issue workforce sanctions",
                "Detected by IT audit on 2025-08-01",
            ],
        },
        # 6. LabCorp — Lab System (LOW risk, ~88/100)
        {
            "name": "LabCorp",
            "legal_name": "Laboratory Corporation of America Holdings",
            "vendor_type": VendorType.LAB_SYSTEM,
            "phi_access": True,
            "phi_types": ["lab_results", "demographics"],
            "data_volume": DataVolume.HIGH,
            "integration_type": ["HL7", "FHIR"],
            "contact_name": "Jennifer Morgan",
            "contact_email": "jmorgan@labcorp.com",
            "contact_phone": "(336) 229-1127",
            "target_score": 88,
            "force_partial": ["PS-02"],  # Physical security documentation
            "baa": {
                "status": BAAStatus.ACTIVE,
                "effective_date": date(2024, 1, 1),
                "expiration_date": date(2027, 12, 31),
                "breach_notification_hours": 24,
                "contingency_notification_hours": 24,
                "subcontractor_flow_down": True,
                "auto_renewal": True,
                "signed_by_vendor": "Adam Schechter",
                "signed_by_org": "Dr. Patricia Whitfield",
            },
            "verification_status": VerificationStatus.VERIFIED,
            "verification_completed": date(2025, 9, 5),
            "onboarded_date": date(2021, 3, 15),
            "notes": [
                "National reference lab — orders and results via HL7/FHIR interface",
                "SOC 2 Type II certified annually",
                "Minor: physical security documentation review requested",
            ],
        },
        # 7. ClearPath SmartSchedule — CLOUD_SERVICE (HIGH risk, ~38/100)
        {
            "name": "ClearPath SmartSchedule",
            "legal_name": "ClearPath Health Technologies Ltd.",
            "vendor_type": VendorType.CLOUD_SERVICE,
            "phi_access": True,
            "phi_types": ["demographics"],
            "data_volume": DataVolume.MEDIUM,
            "integration_type": ["API", "WEB_PORTAL"],
            "contact_name": "Aiden McCarthy",
            "contact_email": "amccarthy@clearpath-health.io",
            "contact_phone": "+353 1 555 0044",
            "target_score": 38,
            "force_no": [
                "AC-02", "EP-03", "EP-04",  # No MFA, partial encryption
                "SM-01", "SM-02", "SM-03",  # No subcontractor management
                "NS-01", "NS-02",  # Network issues
            ],
            "force_unknown": ["VS-04", "VS-05"],
            "baa": {
                "status": BAAStatus.PENDING_SIGNATURE,
                "effective_date": None,
                "expiration_date": None,
                "breach_notification_hours": 72,
                "contingency_notification_hours": 72,
                "subcontractor_flow_down": False,
                "auto_renewal": False,
                "signed_by_vendor": "",
                "signed_by_org": "",
            },
            "verification_status": VerificationStatus.PENDING,
            "verification_due": date(2026, 3, 1),  # Already overdue
            "onboarded_date": date(2025, 10, 1),
            "notes": [
                "Cloud scheduling platform — discovered data hosted in Ireland",
                "CRITICAL: BAA not yet signed — vendor using PHI without agreement",
                "CRITICAL: Data leaves US jurisdiction (EU servers)",
                "No subcontractor flow-down — uses 3rd-party analytics provider",
                "Board review scheduled for April 2026 — potential offboarding",
            ],
        },
        # 8. MedTech Shredding — DESTRUCTION_SERVICE (LOW risk, ~82/100)
        {
            "name": "MedTech Shredding Services",
            "legal_name": "MedTech Document Solutions LLC",
            "vendor_type": VendorType.DESTRUCTION_SERVICE,
            "phi_access": True,
            "phi_types": ["demographics"],
            "data_volume": DataVolume.LOW,
            "integration_type": [],
            "contact_name": "Tom Bradley",
            "contact_email": "tbradley@medtech-shred.com",
            "contact_phone": "(573) 555-0219",
            "target_score": 82,
            "force_partial": ["PS-04"],  # Certificate of destruction tracking
            "baa": {
                "status": BAAStatus.ACTIVE,
                "effective_date": date(2025, 4, 1),
                "expiration_date": date(2027, 3, 31),
                "breach_notification_hours": 24,
                "contingency_notification_hours": 24,
                "subcontractor_flow_down": True,
                "auto_renewal": True,
                "signed_by_vendor": "Tom Bradley",
                "signed_by_org": "Dr. Patricia Whitfield",
            },
            "verification_status": VerificationStatus.VERIFIED,
            "verification_completed": date(2025, 12, 1),
            "onboarded_date": date(2024, 4, 1),
            "notes": [
                "On-site document shredding — biweekly pickup at all 4 locations",
                "NAID AAA certified",
                "Minor gap: certificate-of-destruction tracking needs digitization",
            ],
        },
    ]


# ============================================================================
# Main demo generator
# ============================================================================

def generate_demo_org(
    data_dir: Optional[str] = None,
    verbose: bool = True,
) -> Tuple[VendorDatabase, str]:
    """
    Generate the full Midwest Family Health Partners demo organization.

    Creates 8 vendors with BAAs, assessments, and verifications, then
    prints a colorful summary.

    Args:
        data_dir: Path for the database files. If None, uses a temp directory.
        verbose: Whether to print progress and summary.

    Returns:
        Tuple of (VendorDatabase, data_dir_path).
    """
    rng = random.Random(SEED)

    if data_dir is None:
        data_dir = os.path.join(tempfile.mkdtemp(prefix="vrm_demo_"), "data")

    db = VendorDatabase(data_dir=data_dir)

    if verbose:
        print()
        print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 72}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT}  VerifAI Security — Healthcare Vendor Risk Manager{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Demo Organization Generator{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 72}{Style.RESET_ALL}")
        print()
        print(f"  {Style.BRIGHT}Organization:{Style.RESET_ALL}  {ORG_NAME}")
        print(f"  {Style.BRIGHT}Location:{Style.RESET_ALL}      {ORG_LOCATION}")
        print(f"  {Style.BRIGHT}Description:{Style.RESET_ALL}   {ORG_DESCRIPTION}")
        print()
        print(f"  {Fore.YELLOW}Generating demo data...{Style.RESET_ALL}")
        print()

    vendor_configs = _build_vendors(rng)
    created_vendors = []
    created_baas = []
    created_assessments = []
    created_verifications = []

    for i, cfg in enumerate(vendor_configs, 1):
        # --- Create Vendor ---
        vendor = Vendor(
            name=cfg["name"],
            legal_name=cfg.get("legal_name", ""),
            dba_name=cfg.get("dba_name", ""),
            vendor_type=cfg["vendor_type"],
            tier=VendorTier.MEDIUM,  # Will be reclassified by assessment
            status=VendorStatus.ACTIVE,
            phi_access=cfg["phi_access"],
            phi_types=cfg.get("phi_types", []),
            data_volume=cfg.get("data_volume", DataVolume.NONE),
            integration_type=cfg.get("integration_type", []),
            contact_name=cfg.get("contact_name", ""),
            contact_email=cfg.get("contact_email", ""),
            contact_phone=cfg.get("contact_phone", ""),
            onboarded_date=cfg.get("onboarded_date", date.today()),
            last_review_date=date.today() - timedelta(days=rng.randint(30, 180)),
            next_review_date=date.today() + timedelta(days=rng.randint(30, 365)),
            notes=cfg.get("notes", []),
        )

        # ChatGPT gets special status
        if "ChatGPT" in cfg["name"]:
            vendor.status = VendorStatus.UNDER_REVIEW

        db.save_vendor(vendor)
        created_vendors.append(vendor)

        # --- Create BAA ---
        baa_cfg = cfg.get("baa")
        baa = None
        if baa_cfg is not None:
            baa = BAA(
                vendor_id=vendor.id,
                status=baa_cfg["status"],
                version="2.0" if baa_cfg.get("breach_notification_hours", 72) <= 24 else "1.0",
                effective_date=baa_cfg.get("effective_date"),
                expiration_date=baa_cfg.get("expiration_date"),
                auto_renewal=baa_cfg.get("auto_renewal", False),
                renewal_term_months=12,
                breach_notification_hours=baa_cfg.get("breach_notification_hours", 72),
                contingency_notification_hours=baa_cfg.get("contingency_notification_hours", 72),
                subcontractor_flow_down=baa_cfg.get("subcontractor_flow_down", False),
                signed_by_vendor=baa_cfg.get("signed_by_vendor", ""),
                signed_by_org=baa_cfg.get("signed_by_org", ""),
                document_path=f"/docs/baa/{vendor.name.lower().replace(' ', '_')}_baa_v{('2.0' if baa_cfg.get('breach_notification_hours', 72) <= 24 else '1.0')}.pdf",
                terms=[
                    "PHI use limited to contracted services",
                    "Return/destroy PHI upon termination",
                    f"Breach notification within {baa_cfg.get('breach_notification_hours', 72)} hours",
                    "Subcontractor compliance required" if baa_cfg.get("subcontractor_flow_down") else "No subcontractor flow-down",
                ],
            )
            db.save_baa(baa)
            created_baas.append(baa)

        # --- Run Assessment ---
        questions = get_questions_for_vendor(vendor.vendor_type, vendor.phi_access)
        target = cfg["target_score"]

        responses = _generate_responses(
            questions,
            target,
            rng,
            force_no_ids=cfg.get("force_no"),
            force_partial_ids=cfg.get("force_partial"),
            force_unknown_ids=cfg.get("force_unknown"),
            force_na_ids=cfg.get("force_na"),
        )

        assessment = run_assessment(
            vendor=vendor,
            assessment_type=AssessmentType.ANNUAL,
            responses=responses,
            assessed_by="Nathan Mills, HIPAA Security Official",
            db=db,
        )

        db.save_assessment(assessment)
        created_assessments.append(assessment)

        # Update vendor tier based on assessment
        vendor.tier = VendorTier(assessment.risk_level.lower())
        vendor.last_review_date = date.today()
        db.save_vendor(vendor)

        # --- Create Verification ---
        v_status = cfg.get("verification_status")
        if v_status is not None:
            v_completed = cfg.get("verification_completed")
            v_due = cfg.get("verification_due")

            verification = Verification(
                vendor_id=vendor.id,
                verification_type=VerificationType.ANNUAL_ATTESTATION,
                status=v_status,
                requested_date=(
                    v_completed - timedelta(days=45) if v_completed
                    else (v_due - timedelta(days=60) if v_due else date.today() - timedelta(days=30))
                ),
                due_date=(
                    v_completed + timedelta(days=15) if v_completed
                    else (v_due if v_due else date.today() + timedelta(days=30))
                ),
                completed_date=v_completed,
                verified_by="Dr. Patricia Whitfield" if v_status == VerificationStatus.VERIFIED else "",
                safeguards_confirmed=(
                    [
                        "access_controls", "encryption", "audit_logging",
                        "incident_response", "backup_recovery",
                    ]
                    if v_status == VerificationStatus.VERIFIED else []
                ),
                professional_analysis_attached=v_status == VerificationStatus.VERIFIED,
                authorized_representative_certified=v_status == VerificationStatus.VERIFIED,
                notes=[
                    f"Annual BA verification — {vendor.name}",
                    f"Status: {v_status.value}",
                ],
            )
            db.save_verification(verification)
            created_verifications.append(verification)

        # --- Progress output ---
        if verbose:
            tier_colors = {
                "critical": Fore.RED,
                "high": Fore.YELLOW,
                "medium": Fore.CYAN,
                "low": Fore.GREEN,
            }
            tier_val = assessment.risk_level.lower()
            tier_color = tier_colors.get(tier_val, Fore.WHITE)
            score_color = (
                Fore.GREEN if assessment.overall_score >= 80
                else Fore.YELLOW if assessment.overall_score >= 60
                else Fore.RED
            )

            baa_label = "N/A"
            baa_color = Fore.RED
            if baa is not None:
                baa_label = baa.status.value.upper().replace("_", " ")
                if baa.status == BAAStatus.ACTIVE:
                    baa_color = Fore.GREEN
                elif baa.status in (BAAStatus.RENEWAL_PENDING, BAAStatus.PENDING_SIGNATURE):
                    baa_color = Fore.YELLOW
                else:
                    baa_color = Fore.RED

            findings_count = len(assessment.findings)
            critical_findings = sum(1 for f in assessment.findings if f.severity.value == "critical")

            print(
                f"  {Fore.WHITE}{Style.BRIGHT}[{i}/8]{Style.RESET_ALL} "
                f"{vendor.name:<35} "
                f"Score: {score_color}{assessment.overall_score:5.1f}{Style.RESET_ALL}  "
                f"Tier: {tier_color}{tier_val.upper():<8}{Style.RESET_ALL}  "
                f"BAA: {baa_color}{baa_label:<18}{Style.RESET_ALL}  "
                f"Findings: {Fore.RED if critical_findings else Fore.WHITE}{findings_count}{Style.RESET_ALL}"
            )

    # --- Summary ---
    if verbose:
        print()
        print(f"{Fore.CYAN}{Style.BRIGHT}{'─' * 72}{Style.RESET_ALL}")
        print(f"  {Style.BRIGHT}Demo Generation Complete{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT}{'─' * 72}{Style.RESET_ALL}")
        print()
        print(f"  {Style.BRIGHT}Created:{Style.RESET_ALL}")
        print(f"    Vendors:        {Fore.WHITE}{Style.BRIGHT}{len(created_vendors)}{Style.RESET_ALL}")
        print(f"    BAAs:           {Fore.WHITE}{Style.BRIGHT}{len(created_baas)}{Style.RESET_ALL}")
        print(f"    Assessments:    {Fore.WHITE}{Style.BRIGHT}{len(created_assessments)}{Style.RESET_ALL}")
        print(f"    Verifications:  {Fore.WHITE}{Style.BRIGHT}{len(created_verifications)}{Style.RESET_ALL}")

        total_findings = sum(len(a.findings) for a in created_assessments)
        critical = sum(
            1 for a in created_assessments
            for f in a.findings if f.severity.value == "critical"
        )
        high = sum(
            1 for a in created_assessments
            for f in a.findings if f.severity.value == "high"
        )

        print()
        print(f"  {Style.BRIGHT}Findings:{Style.RESET_ALL}")
        print(f"    Total:    {total_findings}")
        print(f"    Critical: {Fore.RED}{Style.BRIGHT}{critical}{Style.RESET_ALL}")
        print(f"    High:     {Fore.YELLOW}{high}{Style.RESET_ALL}")

        tier_counts = {}
        for v in created_vendors:
            t = v.tier.value
            tier_counts[t] = tier_counts.get(t, 0) + 1

        print()
        print(f"  {Style.BRIGHT}Risk Distribution:{Style.RESET_ALL}")
        for tier_name, color in [
            ("critical", Fore.RED),
            ("high", Fore.YELLOW),
            ("medium", Fore.CYAN),
            ("low", Fore.GREEN),
        ]:
            count = tier_counts.get(tier_name, 0)
            bar = "█" * (count * 4)
            print(f"    {color}{tier_name.upper():<10}{Style.RESET_ALL} {bar} {count}")

        print()
        print(f"  {Style.BRIGHT}Data directory:{Style.RESET_ALL}  {data_dir}")
        print()
        print(
            f"  {Fore.GREEN}Run {Style.BRIGHT}python run_vrm.py dashboard{Style.RESET_ALL}"
            f"{Fore.GREEN} to view the org-wide dashboard{Style.RESET_ALL}"
        )
        print(
            f"  {Fore.GREEN}Run {Style.BRIGHT}python run_vrm.py vendor list{Style.RESET_ALL}"
            f"{Fore.GREEN} to see all vendors by risk{Style.RESET_ALL}"
        )
        print()

    return db, data_dir


# ============================================================================
# Standalone execution
# ============================================================================

if __name__ == "__main__":
    generate_demo_org()
