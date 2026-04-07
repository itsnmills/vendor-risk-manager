"""
Vendor lifecycle management for Vendor Risk Manager.

Handles the complete vendor lifecycle from onboarding through termination,
including dashboard views, risk-sorted listings, expiration alerts,
overdue assessment tracking, and offboarding checklists.

VerifAI Security | Created by Nathan Mills
"""

from datetime import date, datetime, timedelta
from typing import Dict, List, Optional

from .models import (
    AssessmentStatus,
    BAA,
    BAAStatus,
    FindingSeverity,
    FindingStatus,
    Vendor,
    VendorAssessment,
    VendorStatus,
    VendorTier,
    Verification,
    VerificationStatus,
)
from .db import VendorDatabase
from .scoring import calculate_inherent_risk


def onboard_vendor(
    vendor_data: Dict,
    db: VendorDatabase,
) -> Vendor:
    """
    Onboard a new vendor into the risk management system.

    Creates a vendor record with ONBOARDING status, sets the onboarded
    date, calculates initial inherent risk, and persists to the database.

    Args:
        vendor_data: Dictionary containing vendor fields. Must include
                     at minimum 'name'. Optional fields match Vendor dataclass.
        db: VendorDatabase instance for persistence.

    Returns:
        The newly created and persisted Vendor.

    Raises:
        ValueError: If 'name' is not provided in vendor_data.
    """
    if not vendor_data.get("name"):
        raise ValueError("Vendor name is required for onboarding")

    vendor = Vendor(
        name=vendor_data["name"],
        legal_name=vendor_data.get("legal_name", ""),
        dba_name=vendor_data.get("dba_name", ""),
        vendor_type=vendor_data.get("vendor_type", "other"),
        tier=vendor_data.get("tier", "medium"),
        status=VendorStatus.ONBOARDING,
        phi_access=vendor_data.get("phi_access", False),
        phi_types=vendor_data.get("phi_types", []),
        data_volume=vendor_data.get("data_volume", "none"),
        integration_type=vendor_data.get("integration_type", []),
        contact_name=vendor_data.get("contact_name", ""),
        contact_email=vendor_data.get("contact_email", ""),
        contact_phone=vendor_data.get("contact_phone", ""),
        onboarded_date=date.today(),
        notes=vendor_data.get("notes", []),
    )

    # Set initial review date (90 days after onboarding for initial assessment)
    vendor.next_review_date = date.today() + timedelta(days=90)

    return db.save_vendor(vendor)


def update_vendor_status(
    vendor_id: str,
    new_status: VendorStatus,
    reason: str,
    db: VendorDatabase,
) -> Vendor:
    """
    Update a vendor's lifecycle status with audit trail.

    Args:
        vendor_id: UUID of the vendor to update.
        new_status: The new VendorStatus to set.
        reason: Reason for the status change (logged in notes).
        db: VendorDatabase instance.

    Returns:
        Updated Vendor instance.

    Raises:
        ValueError: If vendor not found or invalid status transition.
    """
    vendor = db.get_vendor(vendor_id)
    if vendor is None:
        raise ValueError(f"Vendor '{vendor_id}' not found")

    # Validate status transitions
    valid_transitions = {
        VendorStatus.PROSPECT: {VendorStatus.ONBOARDING, VendorStatus.TERMINATED},
        VendorStatus.ONBOARDING: {VendorStatus.ACTIVE, VendorStatus.TERMINATED},
        VendorStatus.ACTIVE: {
            VendorStatus.UNDER_REVIEW,
            VendorStatus.REMEDIATION,
            VendorStatus.SUSPENDED,
            VendorStatus.OFFBOARDING,
        },
        VendorStatus.UNDER_REVIEW: {
            VendorStatus.ACTIVE,
            VendorStatus.REMEDIATION,
            VendorStatus.SUSPENDED,
            VendorStatus.OFFBOARDING,
        },
        VendorStatus.REMEDIATION: {
            VendorStatus.ACTIVE,
            VendorStatus.UNDER_REVIEW,
            VendorStatus.SUSPENDED,
            VendorStatus.OFFBOARDING,
        },
        VendorStatus.SUSPENDED: {
            VendorStatus.ACTIVE,
            VendorStatus.UNDER_REVIEW,
            VendorStatus.OFFBOARDING,
        },
        VendorStatus.OFFBOARDING: {VendorStatus.TERMINATED},
        VendorStatus.TERMINATED: set(),  # Terminal state
    }

    allowed = valid_transitions.get(vendor.status, set())
    if new_status not in allowed:
        raise ValueError(
            f"Invalid status transition: {vendor.status.value} -> {new_status.value}. "
            f"Allowed: {', '.join(s.value for s in allowed)}"
        )

    old_status = vendor.status.value
    vendor.status = new_status
    vendor.updated_at = datetime.now()
    vendor.notes.append(
        f"[{datetime.now().isoformat()}] Status changed: {old_status} -> "
        f"{new_status.value}. Reason: {reason}"
    )

    # If moving to ACTIVE, set review date
    if new_status == VendorStatus.ACTIVE and vendor.next_review_date is None:
        vendor.next_review_date = date.today() + timedelta(days=365)

    return db.save_vendor(vendor)


def get_vendor_dashboard(
    vendor_id: str,
    db: VendorDatabase,
) -> Dict:
    """
    Build a comprehensive dashboard view for a single vendor.

    Includes vendor details, current BAA status, latest assessment,
    open findings, verification status, inherent risk, and action items.

    Args:
        vendor_id: UUID of the vendor.
        db: VendorDatabase instance.

    Returns:
        Dict with all vendor information organized for display.

    Raises:
        ValueError: If vendor not found.
    """
    vendor = db.get_vendor(vendor_id)
    if vendor is None:
        raise ValueError(f"Vendor '{vendor_id}' not found")

    # Get current BAA
    baas = db.list_baas(vendor_id=vendor_id)
    active_baa = None
    for baa in reversed(baas):
        if baa.status == BAAStatus.ACTIVE:
            active_baa = baa
            break

    # Get latest assessment
    assessments = db.list_assessments(vendor_id=vendor_id)
    latest_assessment = None
    if assessments:
        completed = [a for a in assessments if a.status == AssessmentStatus.COMPLETED]
        if completed:
            latest_assessment = completed[-1]

    # Get open findings
    open_findings = []
    if latest_assessment:
        open_findings = [
            f for f in latest_assessment.findings
            if f.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)
        ]

    # Get latest verification
    verifications = db.list_verifications(vendor_id=vendor_id)
    latest_verification = verifications[-1] if verifications else None

    # Calculate inherent risk
    inherent_risk = calculate_inherent_risk(vendor)

    # Build action items
    action_items: List[str] = []

    if active_baa is None:
        action_items.append("CRITICAL: No active BAA on file")
    elif active_baa.expiration_date:
        days_to_expiry = (active_baa.expiration_date - date.today()).days
        if days_to_expiry < 0:
            action_items.append(f"CRITICAL: BAA expired {abs(days_to_expiry)} days ago")
        elif days_to_expiry <= 90:
            action_items.append(f"WARNING: BAA expires in {days_to_expiry} days")

    if active_baa and active_baa.breach_notification_hours > 24:
        action_items.append(
            "WARNING: BAA breach notification exceeds 24-hour HIPAA requirement "
            f"(currently {active_baa.breach_notification_hours} hours)"
        )

    if latest_assessment is None:
        action_items.append("ACTION: Initial security assessment needed")
    elif latest_assessment.next_due_date and latest_assessment.next_due_date <= date.today():
        action_items.append("ACTION: Assessment is overdue for reassessment")

    critical_findings = [f for f in open_findings if f.severity == FindingSeverity.CRITICAL]
    if critical_findings:
        action_items.append(
            f"CRITICAL: {len(critical_findings)} critical finding(s) require immediate attention"
        )

    overdue_findings = [
        f for f in open_findings
        if f.due_date and f.due_date < date.today()
    ]
    if overdue_findings:
        action_items.append(
            f"WARNING: {len(overdue_findings)} finding(s) past remediation deadline"
        )

    if latest_verification is None and vendor.status == VendorStatus.ACTIVE:
        action_items.append("ACTION: Annual BA verification not yet initiated")
    elif latest_verification and latest_verification.status == VerificationStatus.OVERDUE:
        action_items.append("WARNING: Annual BA verification is overdue")
    elif latest_verification and latest_verification.status == VerificationStatus.FAILED:
        action_items.append("CRITICAL: Annual BA verification failed")

    return {
        "vendor": vendor.to_dict(),
        "inherent_risk_score": inherent_risk,
        "current_baa": active_baa.to_dict() if active_baa else None,
        "latest_assessment": {
            "id": latest_assessment.id,
            "type": latest_assessment.assessment_type.value,
            "overall_score": latest_assessment.overall_score,
            "risk_level": latest_assessment.risk_level,
            "completed_date": latest_assessment.completed_date.isoformat() if latest_assessment.completed_date else None,
            "next_due_date": latest_assessment.next_due_date.isoformat() if latest_assessment.next_due_date else None,
            "domain_scores": latest_assessment.domain_scores,
        } if latest_assessment else None,
        "open_findings": {
            "total": len(open_findings),
            "critical": sum(1 for f in open_findings if f.severity == FindingSeverity.CRITICAL),
            "high": sum(1 for f in open_findings if f.severity == FindingSeverity.HIGH),
            "medium": sum(1 for f in open_findings if f.severity == FindingSeverity.MEDIUM),
            "low": sum(1 for f in open_findings if f.severity == FindingSeverity.LOW),
            "overdue": len(overdue_findings),
            "findings": [f.to_dict() for f in open_findings],
        },
        "verification": latest_verification.to_dict() if latest_verification else None,
        "action_items": action_items,
        "strengths": latest_assessment.strengths if latest_assessment else [],
    }


def list_vendors_by_risk(db: VendorDatabase) -> List[Dict]:
    """
    List all vendors sorted by risk level (highest risk first).

    Calculates inherent risk for each vendor and sorts by risk score
    descending. Includes BAA status and assessment status for each.

    Args:
        db: VendorDatabase instance.

    Returns:
        List of dicts with vendor summary and risk information.
    """
    vendors = db.list_vendors()
    vendor_risks = []

    for vendor in vendors:
        inherent = calculate_inherent_risk(vendor)

        # Get latest assessment score
        assessments = db.list_assessments(vendor_id=vendor.id)
        latest_score = None
        risk_level = "UNASSESSED"
        for assessment in reversed(assessments):
            if assessment.status == AssessmentStatus.COMPLETED:
                latest_score = assessment.overall_score
                risk_level = assessment.risk_level
                break

        # Get BAA status
        baas = db.list_baas(vendor_id=vendor.id)
        baa_status = "MISSING"
        for baa in reversed(baas):
            if baa.status == BAAStatus.ACTIVE:
                baa_status = "ACTIVE"
                if baa.expiration_date and baa.expiration_date <= date.today():
                    baa_status = "EXPIRED"
                elif baa.expiration_date and (baa.expiration_date - date.today()).days <= 90:
                    baa_status = "EXPIRING_SOON"
                break

        # Sort key: unassessed vendors go to top, then by risk
        sort_key = 0.0
        if latest_score is not None:
            # Lower score = higher risk, so invert for sorting
            sort_key = 100.0 - latest_score
        else:
            sort_key = 200.0  # Unassessed vendors are highest priority

        vendor_risks.append({
            "vendor_id": vendor.id,
            "vendor_name": vendor.name,
            "vendor_type": vendor.vendor_type.value,
            "status": vendor.status.value,
            "tier": vendor.tier.value,
            "phi_access": vendor.phi_access,
            "inherent_risk": inherent,
            "assessment_score": latest_score,
            "risk_level": risk_level,
            "baa_status": baa_status,
            "_sort_key": sort_key,
        })

    # Sort by risk (highest first)
    vendor_risks.sort(key=lambda v: v["_sort_key"], reverse=True)

    # Remove sort key from output
    for v in vendor_risks:
        del v["_sort_key"]

    return vendor_risks


def get_expiring_baas(
    db: VendorDatabase,
    days_ahead: int = 90,
) -> List[Dict]:
    """
    Find BAAs that are expiring within the specified number of days.

    Args:
        db: VendorDatabase instance.
        days_ahead: Number of days to look ahead for expirations.

    Returns:
        List of dicts with BAA and vendor details for expiring agreements.
    """
    cutoff = date.today() + timedelta(days=days_ahead)
    results = []

    for baa in db.list_baas():
        if baa.status != BAAStatus.ACTIVE:
            continue
        if baa.expiration_date is None:
            continue
        if baa.expiration_date <= cutoff:
            vendor = db.get_vendor(baa.vendor_id)
            days_remaining = (baa.expiration_date - date.today()).days

            results.append({
                "baa_id": baa.id,
                "vendor_id": baa.vendor_id,
                "vendor_name": vendor.name if vendor else "Unknown",
                "expiration_date": baa.expiration_date.isoformat(),
                "days_remaining": days_remaining,
                "auto_renewal": baa.auto_renewal,
                "is_expired": days_remaining < 0,
                "urgency": (
                    "EXPIRED" if days_remaining < 0
                    else "CRITICAL" if days_remaining <= 30
                    else "WARNING" if days_remaining <= 60
                    else "NOTICE"
                ),
            })

    # Sort by days remaining (most urgent first)
    results.sort(key=lambda x: x["days_remaining"])
    return results


def get_overdue_assessments(db: VendorDatabase) -> List[Dict]:
    """
    Find vendors that need reassessment (past their next due date).

    Also includes active vendors that have never been assessed.

    Args:
        db: VendorDatabase instance.

    Returns:
        List of dicts with vendor details and overdue information.
    """
    results = []
    today = date.today()

    for vendor in db.list_vendors():
        # Skip non-active vendors (except ONBOARDING which needs initial assessment)
        if vendor.status not in (
            VendorStatus.ACTIVE,
            VendorStatus.ONBOARDING,
            VendorStatus.UNDER_REVIEW,
            VendorStatus.REMEDIATION,
        ):
            continue

        assessments = db.list_assessments(vendor_id=vendor.id)
        completed = [a for a in assessments if a.status == AssessmentStatus.COMPLETED]

        if not completed:
            # Never assessed
            days_overdue = (today - vendor.onboarded_date).days if vendor.onboarded_date else 0
            results.append({
                "vendor_id": vendor.id,
                "vendor_name": vendor.name,
                "vendor_status": vendor.status.value,
                "phi_access": vendor.phi_access,
                "last_assessment_date": None,
                "next_due_date": None,
                "days_overdue": days_overdue,
                "reason": "Never assessed",
                "urgency": "CRITICAL" if vendor.phi_access else "HIGH",
            })
        else:
            latest = completed[-1]
            if latest.next_due_date and latest.next_due_date <= today:
                days_overdue = (today - latest.next_due_date).days
                results.append({
                    "vendor_id": vendor.id,
                    "vendor_name": vendor.name,
                    "vendor_status": vendor.status.value,
                    "phi_access": vendor.phi_access,
                    "last_assessment_date": latest.completed_date.isoformat() if latest.completed_date else None,
                    "next_due_date": latest.next_due_date.isoformat(),
                    "days_overdue": days_overdue,
                    "reason": "Assessment overdue",
                    "urgency": (
                        "CRITICAL" if days_overdue > 90
                        else "HIGH" if days_overdue > 30
                        else "WARNING"
                    ),
                })

    # Sort by urgency then days overdue
    urgency_order = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "NOTICE": 3}
    results.sort(key=lambda x: (urgency_order.get(x["urgency"], 99), -x["days_overdue"]))
    return results


def get_vendors_needing_verification(db: VendorDatabase) -> List[Dict]:
    """
    Find active vendors that need annual BA verification.

    Checks for vendors without any verification, vendors with expired
    verifications, or vendors past the annual verification date.

    Args:
        db: VendorDatabase instance.

    Returns:
        List of dicts with vendor details and verification status.
    """
    results = []
    today = date.today()

    for vendor in db.list_vendors():
        if vendor.status not in (VendorStatus.ACTIVE, VendorStatus.UNDER_REVIEW):
            continue
        if not vendor.phi_access:
            continue  # Only PHI-handling vendors need verification

        verifications = db.list_verifications(vendor_id=vendor.id)

        if not verifications:
            results.append({
                "vendor_id": vendor.id,
                "vendor_name": vendor.name,
                "last_verification_date": None,
                "verification_status": "NEVER_VERIFIED",
                "reason": "No verification on record",
                "urgency": "HIGH",
            })
            continue

        latest = verifications[-1]

        if latest.status in (VerificationStatus.OVERDUE, VerificationStatus.FAILED):
            results.append({
                "vendor_id": vendor.id,
                "vendor_name": vendor.name,
                "last_verification_date": latest.completed_date.isoformat() if latest.completed_date else None,
                "verification_status": latest.status.value,
                "reason": f"Verification {latest.status.value}",
                "urgency": "CRITICAL" if latest.status == VerificationStatus.FAILED else "HIGH",
            })
            continue

        # Check if verification is older than 1 year
        if latest.status == VerificationStatus.VERIFIED and latest.completed_date:
            age = (today - latest.completed_date).days
            if age > 365:
                results.append({
                    "vendor_id": vendor.id,
                    "vendor_name": vendor.name,
                    "last_verification_date": latest.completed_date.isoformat(),
                    "verification_status": "EXPIRED",
                    "reason": f"Last verification {age} days ago (annual required)",
                    "urgency": "HIGH",
                })
        elif latest.status == VerificationStatus.PENDING:
            if latest.due_date and latest.due_date < today:
                results.append({
                    "vendor_id": vendor.id,
                    "vendor_name": vendor.name,
                    "last_verification_date": None,
                    "verification_status": "OVERDUE",
                    "reason": f"Verification request pending, due date passed",
                    "urgency": "HIGH",
                })

    # Sort by urgency
    urgency_order = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "NOTICE": 3}
    results.sort(key=lambda x: urgency_order.get(x["urgency"], 99))
    return results


def offboard_vendor(
    vendor_id: str,
    db: VendorDatabase,
    reason: str = "Contract termination",
) -> Dict:
    """
    Initiate vendor offboarding with compliance checklist.

    Moves the vendor to OFFBOARDING status and generates a checklist
    of required actions for compliant termination.

    Args:
        vendor_id: UUID of the vendor to offboard.
        db: VendorDatabase instance.
        reason: Reason for offboarding.

    Returns:
        Dict containing the vendor, offboarding checklist, and status.

    Raises:
        ValueError: If vendor not found or already terminated.
    """
    vendor = db.get_vendor(vendor_id)
    if vendor is None:
        raise ValueError(f"Vendor '{vendor_id}' not found")
    if vendor.status == VendorStatus.TERMINATED:
        raise ValueError(f"Vendor '{vendor.name}' is already terminated")

    # Move to offboarding (or directly to terminated if already offboarding)
    if vendor.status != VendorStatus.OFFBOARDING:
        vendor.status = VendorStatus.OFFBOARDING
        vendor.updated_at = datetime.now()
        vendor.notes.append(
            f"[{datetime.now().isoformat()}] Offboarding initiated. Reason: {reason}"
        )
        db.save_vendor(vendor)

    # Generate offboarding checklist
    checklist = [
        {
            "item": "Terminate BAA",
            "description": "Execute BAA termination provisions and document effective date",
            "status": "pending",
            "required": True,
        },
        {
            "item": "Revoke Access",
            "description": "Ensure all vendor access to covered entity systems is revoked",
            "status": "pending",
            "required": True,
        },
        {
            "item": "ePHI Return/Destruction",
            "description": "Obtain written confirmation of ePHI return or destruction per BAA terms",
            "status": "pending",
            "required": True,
        },
        {
            "item": "Certificate of Destruction",
            "description": "Request certificate of destruction for all ePHI media (NIST 800-88)",
            "status": "pending",
            "required": vendor.phi_access,
        },
        {
            "item": "Subcontractor Notification",
            "description": "Verify vendor has notified and terminated ePHI access for all subcontractors",
            "status": "pending",
            "required": True,
        },
        {
            "item": "Final Assessment",
            "description": "Conduct offboarding security assessment to document security posture at termination",
            "status": "pending",
            "required": False,
        },
        {
            "item": "Credential Rotation",
            "description": "Rotate any shared credentials, API keys, or certificates used by vendor",
            "status": "pending",
            "required": True,
        },
        {
            "item": "Network Access Removal",
            "description": "Remove all VPN, firewall rules, and network access for vendor",
            "status": "pending",
            "required": True,
        },
        {
            "item": "Integration Decommission",
            "description": "Disable all HL7/FHIR/API integrations with vendor systems",
            "status": "pending",
            "required": bool(vendor.integration_type),
        },
        {
            "item": "Documentation Archival",
            "description": "Archive all vendor documentation, assessments, and correspondence (6-year retention)",
            "status": "pending",
            "required": True,
        },
        {
            "item": "Final BAA Compliance Check",
            "description": "Verify all BAA termination requirements have been satisfied",
            "status": "pending",
            "required": True,
        },
    ]

    # Filter to required items and applicable items
    applicable_checklist = [
        item for item in checklist
        if item["required"]
    ]

    return {
        "vendor": vendor.to_dict(),
        "offboarding_reason": reason,
        "initiated_date": datetime.now().isoformat(),
        "checklist": applicable_checklist,
        "total_items": len(applicable_checklist),
        "completed_items": sum(1 for item in applicable_checklist if item["status"] == "completed"),
        "notes": [
            "All checklist items must be completed before moving to TERMINATED status",
            "Document completion of each item with date and responsible party",
            "Retain all offboarding documentation for minimum 6 years per HIPAA",
        ],
    }
