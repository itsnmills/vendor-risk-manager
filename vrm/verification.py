"""
Annual Business Associate verification workflow.

Implements the new HIPAA requirement for annual BA verification, which
requires covered entities to obtain:
    1. Written verification from the BA confirming technical safeguards deployed
    2. Written analysis from a qualified professional
    3. Certification by an authorized representative

All three components must be present for VERIFIED status.

VerifAI Security | Created by Nathan Mills
"""

from datetime import date, datetime, timedelta
from typing import Dict, List, Optional

from .models import (
    Vendor,
    VendorStatus,
    Verification,
    VerificationType,
    VerificationStatus,
)
from .db import VendorDatabase


# Default verification due date: 60 days from request
DEFAULT_VERIFICATION_DUE_DAYS = 60

# Required safeguards for verification (minimum expected)
REQUIRED_SAFEGUARD_CATEGORIES = [
    "access_controls",
    "encryption",
    "audit_logging",
    "incident_response",
    "backup_recovery",
]


def create_verification_request(
    vendor_id: str,
    db: VendorDatabase,
    verification_type: VerificationType = VerificationType.ANNUAL_ATTESTATION,
    due_days: int = DEFAULT_VERIFICATION_DUE_DAYS,
    notes: Optional[List[str]] = None,
) -> Verification:
    """
    Create a new verification request for a vendor.

    Initiates the annual BA verification workflow by creating a PENDING
    verification record with a due date.

    Args:
        vendor_id: UUID of the vendor to verify.
        db: VendorDatabase instance.
        verification_type: Type of verification being requested.
        due_days: Number of days until verification is due.
        notes: Optional initial notes.

    Returns:
        The newly created Verification with PENDING status.

    Raises:
        ValueError: If vendor not found or not in verifiable state.
    """
    vendor = db.get_vendor(vendor_id)
    if vendor is None:
        raise ValueError(f"Vendor '{vendor_id}' not found")

    if vendor.status not in (
        VendorStatus.ACTIVE,
        VendorStatus.UNDER_REVIEW,
        VendorStatus.ONBOARDING,
    ):
        raise ValueError(
            f"Cannot create verification for vendor in '{vendor.status.value}' status. "
            f"Vendor must be ACTIVE, UNDER_REVIEW, or ONBOARDING."
        )

    # Check for existing pending verification
    existing = db.list_verifications(vendor_id=vendor_id)
    pending = [
        v for v in existing
        if v.status in (VerificationStatus.PENDING, VerificationStatus.SUBMITTED)
    ]
    if pending:
        raise ValueError(
            f"Vendor '{vendor.name}' already has a pending verification request "
            f"(ID: {pending[0].id}). Complete or cancel it before creating a new one."
        )

    verification = Verification(
        vendor_id=vendor_id,
        verification_type=verification_type,
        status=VerificationStatus.PENDING,
        requested_date=date.today(),
        due_date=date.today() + timedelta(days=due_days),
        notes=notes or [
            f"Verification request created on {date.today().isoformat()}",
            f"Due date: {(date.today() + timedelta(days=due_days)).isoformat()}",
            "Required: (1) Written safeguard confirmation, "
            "(2) Professional analysis, "
            "(3) Authorized representative certification",
        ],
    )

    return db.save_verification(verification)


def submit_verification(
    verification_id: str,
    safeguards_confirmed: List[str],
    professional_analysis: bool,
    authorized_certification: bool,
    db: VendorDatabase,
    verified_by: str = "",
    notes: Optional[List[str]] = None,
) -> Verification:
    """
    Submit a vendor's verification response.

    Records the three required components of the annual BA verification:
    safeguards confirmed, professional analysis, and authorized certification.

    Args:
        verification_id: UUID of the verification request.
        safeguards_confirmed: List of safeguard categories confirmed by the BA.
            Expected categories include: access_controls, encryption,
            audit_logging, incident_response, backup_recovery, and others.
        professional_analysis: Whether a written analysis from a qualified
            professional is attached.
        authorized_certification: Whether an authorized representative has
            certified the verification.
        db: VendorDatabase instance.
        verified_by: Name/title of the person submitting the verification.
        notes: Optional submission notes.

    Returns:
        Updated Verification with SUBMITTED status.

    Raises:
        ValueError: If verification not found or not in submittable state.
    """
    verification = db.get_verification(verification_id)
    if verification is None:
        raise ValueError(f"Verification '{verification_id}' not found")

    if verification.status not in (VerificationStatus.PENDING, VerificationStatus.OVERDUE):
        raise ValueError(
            f"Verification is in '{verification.status.value}' status and cannot be submitted. "
            f"Only PENDING or OVERDUE verifications can be submitted."
        )

    verification.status = VerificationStatus.SUBMITTED
    verification.safeguards_confirmed = safeguards_confirmed
    verification.professional_analysis_attached = professional_analysis
    verification.authorized_representative_certified = authorized_certification
    verification.verified_by = verified_by
    verification.updated_at = datetime.now()

    submission_notes = [
        f"[{datetime.now().isoformat()}] Verification submitted by {verified_by}",
        f"Safeguards confirmed: {', '.join(safeguards_confirmed)}",
        f"Professional analysis attached: {professional_analysis}",
        f"Authorized representative certified: {authorized_certification}",
    ]
    if notes:
        submission_notes.extend(notes)
    verification.notes.extend(submission_notes)

    return db.save_verification(verification)


def review_verification(
    verification_id: str,
    db: VendorDatabase,
    reviewer: str = "",
) -> Dict:
    """
    Review a submitted verification and determine pass/fail.

    Evaluates the three required components:
        1. Written verification confirming technical safeguards deployed
        2. Written analysis from a qualified professional
        3. Certification by an authorized representative

    All three must be present and adequate for VERIFIED status.

    Args:
        verification_id: UUID of the verification to review.
        db: VendorDatabase instance.
        reviewer: Name of the person conducting the review.

    Returns:
        Dict with review results, status, and any failure reasons.

    Raises:
        ValueError: If verification not found or not in reviewable state.
    """
    verification = db.get_verification(verification_id)
    if verification is None:
        raise ValueError(f"Verification '{verification_id}' not found")

    if verification.status != VerificationStatus.SUBMITTED:
        raise ValueError(
            f"Verification is in '{verification.status.value}' status. "
            f"Only SUBMITTED verifications can be reviewed."
        )

    vendor = db.get_vendor(verification.vendor_id)
    vendor_name = vendor.name if vendor else "Unknown"

    # Evaluate each component
    checks: Dict[str, Dict] = {}
    failures: List[str] = []

    # Check 1: Safeguards confirmed
    confirmed_set = set(verification.safeguards_confirmed)
    required_set = set(REQUIRED_SAFEGUARD_CATEGORIES)
    missing_safeguards = required_set - confirmed_set
    safeguards_pass = len(missing_safeguards) == 0 and len(verification.safeguards_confirmed) > 0

    checks["safeguards_confirmed"] = {
        "passed": safeguards_pass,
        "confirmed": verification.safeguards_confirmed,
        "required": REQUIRED_SAFEGUARD_CATEGORIES,
        "missing": list(missing_safeguards),
        "detail": (
            f"All {len(REQUIRED_SAFEGUARD_CATEGORIES)} required safeguard categories confirmed, "
            f"plus {len(confirmed_set - required_set)} additional categories"
            if safeguards_pass
            else f"Missing safeguard confirmations: {', '.join(missing_safeguards)}"
        ),
    }
    if not safeguards_pass:
        failures.append(
            f"Incomplete safeguard confirmation — missing: {', '.join(missing_safeguards)}"
        )

    # Check 2: Professional analysis
    analysis_pass = verification.professional_analysis_attached
    checks["professional_analysis"] = {
        "passed": analysis_pass,
        "attached": analysis_pass,
        "detail": (
            "Written analysis from qualified professional is attached"
            if analysis_pass
            else "Written analysis from qualified professional is NOT attached. "
                 "This is a mandatory requirement under the new HIPAA verification rules."
        ),
    }
    if not analysis_pass:
        failures.append(
            "Missing written analysis from a qualified professional"
        )

    # Check 3: Authorized representative certification
    cert_pass = verification.authorized_representative_certified
    checks["authorized_certification"] = {
        "passed": cert_pass,
        "certified": cert_pass,
        "detail": (
            "Authorized representative has certified the verification"
            if cert_pass
            else "Authorized representative certification is NOT present. "
                 "A designated authorized representative must certify the verification."
        ),
    }
    if not cert_pass:
        failures.append(
            "Missing certification by authorized representative"
        )

    # Determine overall result
    all_passed = safeguards_pass and analysis_pass and cert_pass

    if all_passed:
        verification.status = VerificationStatus.VERIFIED
        verification.completed_date = date.today()
        result_status = "VERIFIED"
    else:
        verification.status = VerificationStatus.FAILED
        verification.completed_date = date.today()
        result_status = "FAILED"

    verification.updated_at = datetime.now()
    verification.notes.append(
        f"[{datetime.now().isoformat()}] Review completed by {reviewer}. "
        f"Result: {result_status}. "
        + (f"Failures: {'; '.join(failures)}" if failures else "All checks passed.")
    )

    db.save_verification(verification)

    return {
        "verification_id": verification.id,
        "vendor_id": verification.vendor_id,
        "vendor_name": vendor_name,
        "result": result_status,
        "reviewed_by": reviewer,
        "reviewed_date": date.today().isoformat(),
        "checks": checks,
        "failures": failures,
        "all_checks_passed": all_passed,
        "recommendations": (
            []
            if all_passed
            else [
                f"Address the following before resubmitting: {'; '.join(failures)}",
                "A new verification submission will be required after addressing these items",
            ]
        ),
    }


def get_verification_status_report(db: VendorDatabase) -> Dict:
    """
    Generate an organization-wide verification status report.

    Provides a summary of all vendor verification statuses including
    verified, pending, failed, overdue, and never-verified counts.

    Args:
        db: VendorDatabase instance.

    Returns:
        Dict with comprehensive verification status breakdown and
        vendor-level details.
    """
    today = date.today()
    all_vendors = db.list_vendors()
    all_verifications = db.list_verifications()

    # Group verifications by vendor
    vendor_verifications: Dict[str, List[Verification]] = {}
    for v in all_verifications:
        if v.vendor_id not in vendor_verifications:
            vendor_verifications[v.vendor_id] = []
        vendor_verifications[v.vendor_id].append(v)

    # Analyze each active vendor
    vendor_statuses: List[Dict] = []
    status_counts = {
        "verified": 0,
        "pending": 0,
        "submitted": 0,
        "under_review": 0,
        "failed": 0,
        "overdue": 0,
        "never_verified": 0,
        "not_required": 0,
    }

    for vendor in all_vendors:
        # Non-active vendors or non-PHI vendors don't require verification
        if vendor.status not in (VendorStatus.ACTIVE, VendorStatus.UNDER_REVIEW):
            status_counts["not_required"] += 1
            continue
        if not vendor.phi_access:
            status_counts["not_required"] += 1
            continue

        verifications = vendor_verifications.get(vendor.id, [])

        if not verifications:
            status_counts["never_verified"] += 1
            vendor_statuses.append({
                "vendor_id": vendor.id,
                "vendor_name": vendor.name,
                "status": "NEVER_VERIFIED",
                "last_verified_date": None,
                "days_since_verification": None,
                "needs_action": True,
            })
            continue

        latest = verifications[-1]

        # Check for overdue pending verifications
        if (latest.status == VerificationStatus.PENDING
                and latest.due_date
                and latest.due_date < today):
            # Mark as overdue
            latest.status = VerificationStatus.OVERDUE
            latest.updated_at = datetime.now()
            latest.notes.append(
                f"[{datetime.now().isoformat()}] Automatically marked OVERDUE — "
                f"due date {latest.due_date.isoformat()} has passed"
            )
            db.save_verification(latest)

        status_key = latest.status.value
        if status_key in status_counts:
            status_counts[status_key] += 1
        else:
            status_counts[status_key] = 1

        # Check if annual verification is stale (>365 days old)
        days_since = None
        is_stale = False
        if latest.completed_date:
            days_since = (today - latest.completed_date).days
            is_stale = days_since > 365

        needs_action = latest.status in (
            VerificationStatus.PENDING,
            VerificationStatus.FAILED,
            VerificationStatus.OVERDUE,
        ) or is_stale

        vendor_statuses.append({
            "vendor_id": vendor.id,
            "vendor_name": vendor.name,
            "status": "STALE" if is_stale and latest.status == VerificationStatus.VERIFIED else latest.status.value,
            "last_verified_date": latest.completed_date.isoformat() if latest.completed_date else None,
            "days_since_verification": days_since,
            "due_date": latest.due_date.isoformat() if latest.due_date else None,
            "needs_action": needs_action,
        })

    # Calculate compliance percentage
    total_required = sum(
        status_counts[k] for k in status_counts
        if k != "not_required"
    )
    verified_count = status_counts["verified"]
    compliance_pct = (
        round(verified_count / total_required * 100, 1)
        if total_required > 0 else 0.0
    )

    return {
        "report_date": today.isoformat(),
        "total_vendors": len(all_vendors),
        "verification_required": total_required,
        "not_required": status_counts["not_required"],
        "status_breakdown": status_counts,
        "compliance_percentage": compliance_pct,
        "vendors_needing_action": [
            v for v in vendor_statuses if v["needs_action"]
        ],
        "all_vendor_statuses": vendor_statuses,
    }


def get_overdue_verifications(db: VendorDatabase) -> List[Dict]:
    """
    Find all vendors with overdue or missing annual verifications.

    Includes vendors whose verification is past due date, vendors that
    have never been verified, and vendors whose last verification is
    older than one year.

    Args:
        db: VendorDatabase instance.

    Returns:
        List of dicts with vendor details and overdue information,
        sorted by urgency.
    """
    today = date.today()
    results: List[Dict] = []

    for vendor in db.list_vendors():
        if vendor.status not in (VendorStatus.ACTIVE, VendorStatus.UNDER_REVIEW):
            continue
        if not vendor.phi_access:
            continue

        verifications = db.list_verifications(vendor_id=vendor.id)

        if not verifications:
            # Never verified
            days_active = (today - vendor.onboarded_date).days if vendor.onboarded_date else 0
            results.append({
                "vendor_id": vendor.id,
                "vendor_name": vendor.name,
                "reason": "Never verified",
                "days_overdue": days_active,
                "last_verified": None,
                "urgency": "CRITICAL" if days_active > 365 else "HIGH",
                "recommended_action": "Create verification request immediately",
            })
            continue

        latest = verifications[-1]

        # Check if pending and past due
        if (latest.status in (VerificationStatus.PENDING, VerificationStatus.OVERDUE)
                and latest.due_date
                and latest.due_date < today):
            days_overdue = (today - latest.due_date).days
            results.append({
                "vendor_id": vendor.id,
                "vendor_name": vendor.name,
                "reason": "Verification request past due",
                "days_overdue": days_overdue,
                "last_verified": None,
                "due_date": latest.due_date.isoformat(),
                "urgency": "CRITICAL" if days_overdue > 30 else "HIGH",
                "recommended_action": "Escalate to vendor contact for immediate response",
            })
            continue

        # Check if failed and not resubmitted
        if latest.status == VerificationStatus.FAILED:
            results.append({
                "vendor_id": vendor.id,
                "vendor_name": vendor.name,
                "reason": "Verification failed — resubmission required",
                "days_overdue": 0,
                "last_verified": latest.completed_date.isoformat() if latest.completed_date else None,
                "urgency": "CRITICAL",
                "recommended_action": "Work with vendor to address failures and resubmit",
            })
            continue

        # Check if verified but older than 1 year
        if latest.status == VerificationStatus.VERIFIED and latest.completed_date:
            age = (today - latest.completed_date).days
            if age > 365:
                days_overdue = age - 365
                results.append({
                    "vendor_id": vendor.id,
                    "vendor_name": vendor.name,
                    "reason": f"Annual verification expired ({age} days since last verification)",
                    "days_overdue": days_overdue,
                    "last_verified": latest.completed_date.isoformat(),
                    "urgency": "HIGH" if days_overdue > 90 else "WARNING",
                    "recommended_action": "Create new annual verification request",
                })

    # Sort by urgency
    urgency_order = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "NOTICE": 3}
    results.sort(key=lambda x: (urgency_order.get(x["urgency"], 99), -x.get("days_overdue", 0)))
    return results
