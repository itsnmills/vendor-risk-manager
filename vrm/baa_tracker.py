"""
Business Associate Agreement (BAA) lifecycle management.

Handles BAA creation, status tracking, compliance checking against
new HIPAA requirements (24-hour breach notification, 24-hour contingency
plan activation notification), expiration alerts, and renewal workflows.

VerifAI Security | Created by Nathan Mills
"""

from datetime import date, datetime, timedelta
from typing import Dict, List, Optional

from .models import (
    BAA,
    BAAStatus,
    Vendor,
    VendorStatus,
)
from .db import VendorDatabase


# Maximum breach notification hours under new HIPAA rules
HIPAA_BREACH_NOTIFICATION_HOURS = 24
HIPAA_CONTINGENCY_NOTIFICATION_HOURS = 24


def create_baa(
    vendor_id: str,
    terms: Dict,
    db: VendorDatabase,
) -> BAA:
    """
    Create a new Business Associate Agreement.

    Args:
        vendor_id: UUID of the vendor this BAA covers.
        terms: Dictionary of BAA terms including:
            - version (str): BAA version identifier
            - effective_date (date): When BAA takes effect
            - expiration_date (date): When BAA expires
            - auto_renewal (bool): Whether BAA auto-renews
            - renewal_term_months (int): Auto-renewal term length
            - breach_notification_hours (int): Hours for breach notification
            - contingency_notification_hours (int): Hours for contingency notification
            - subcontractor_flow_down (bool): Requires subcontractor compliance
            - signed_by_vendor (str): Vendor signatory name
            - signed_by_org (str): Organization signatory name
            - document_path (str): Path to BAA document file
            - terms (list): List of key terms being tracked
            - notes (list): Additional notes
        db: VendorDatabase instance.

    Returns:
        The newly created BAA.

    Raises:
        ValueError: If vendor not found.
    """
    vendor = db.get_vendor(vendor_id)
    if vendor is None:
        raise ValueError(f"Vendor '{vendor_id}' not found")

    baa = BAA(
        vendor_id=vendor_id,
        status=BAAStatus.DRAFT,
        version=terms.get("version", "1.0"),
        effective_date=terms.get("effective_date"),
        expiration_date=terms.get("expiration_date"),
        auto_renewal=terms.get("auto_renewal", False),
        renewal_term_months=terms.get("renewal_term_months", 12),
        breach_notification_hours=terms.get("breach_notification_hours", 72),
        contingency_notification_hours=terms.get("contingency_notification_hours", 72),
        subcontractor_flow_down=terms.get("subcontractor_flow_down", False),
        signed_by_vendor=terms.get("signed_by_vendor", ""),
        signed_by_org=terms.get("signed_by_org", ""),
        document_path=terms.get("document_path", ""),
        terms=terms.get("terms", []),
        notes=terms.get("notes", []),
    )

    return db.save_baa(baa)


def update_baa_status(
    baa_id: str,
    new_status: BAAStatus,
    db: VendorDatabase,
    reason: str = "",
) -> BAA:
    """
    Update a BAA's lifecycle status.

    Args:
        baa_id: UUID of the BAA to update.
        new_status: The new BAAStatus.
        db: VendorDatabase instance.
        reason: Optional reason for the status change.

    Returns:
        Updated BAA instance.

    Raises:
        ValueError: If BAA not found or invalid transition.
    """
    baa = db.get_baa(baa_id)
    if baa is None:
        raise ValueError(f"BAA '{baa_id}' not found")

    valid_transitions = {
        BAAStatus.DRAFT: {BAAStatus.PENDING_REVIEW, BAAStatus.TERMINATED},
        BAAStatus.PENDING_REVIEW: {BAAStatus.PENDING_SIGNATURE, BAAStatus.DRAFT, BAAStatus.TERMINATED},
        BAAStatus.PENDING_SIGNATURE: {BAAStatus.ACTIVE, BAAStatus.DRAFT, BAAStatus.TERMINATED},
        BAAStatus.ACTIVE: {BAAStatus.EXPIRED, BAAStatus.TERMINATED, BAAStatus.RENEWAL_PENDING},
        BAAStatus.RENEWAL_PENDING: {BAAStatus.ACTIVE, BAAStatus.EXPIRED, BAAStatus.TERMINATED},
        BAAStatus.EXPIRED: {BAAStatus.RENEWAL_PENDING, BAAStatus.TERMINATED},
        BAAStatus.TERMINATED: set(),
    }

    allowed = valid_transitions.get(baa.status, set())
    if new_status not in allowed:
        raise ValueError(
            f"Invalid BAA status transition: {baa.status.value} -> {new_status.value}. "
            f"Allowed: {', '.join(s.value for s in allowed)}"
        )

    old_status = baa.status.value
    baa.status = new_status
    baa.last_updated_date = date.today()
    baa.updated_at = datetime.now()

    note = f"[{datetime.now().isoformat()}] Status changed: {old_status} -> {new_status.value}"
    if reason:
        note += f". Reason: {reason}"
    baa.notes.append(note)

    return db.save_baa(baa)


def check_baa_compliance(
    baa_id: str,
    db: VendorDatabase,
) -> Dict:
    """
    Check a BAA's compliance with current HIPAA requirements.

    Evaluates:
        - Breach notification timeline (must be ≤24 hours under new rules)
        - Contingency notification timeline (must be ≤24 hours under new rules)
        - Subcontractor flow-down provisions
        - Expiration status
        - Signature completeness
        - Document availability

    Args:
        baa_id: UUID of the BAA to check.
        db: VendorDatabase instance.

    Returns:
        Dict with compliance check results and recommendations.

    Raises:
        ValueError: If BAA not found.
    """
    baa = db.get_baa(baa_id)
    if baa is None:
        raise ValueError(f"BAA '{baa_id}' not found")

    vendor = db.get_vendor(baa.vendor_id)
    vendor_name = vendor.name if vendor else "Unknown"

    checks: Dict[str, Dict] = {}

    # Breach notification compliance (24 hours under new HIPAA)
    breach_compliant = baa.breach_notification_hours <= HIPAA_BREACH_NOTIFICATION_HOURS
    checks["breach_notification_compliant"] = {
        "compliant": breach_compliant,
        "current_value": f"{baa.breach_notification_hours} hours",
        "required_value": f"{HIPAA_BREACH_NOTIFICATION_HOURS} hours",
        "detail": (
            "BAA meets 24-hour breach notification requirement"
            if breach_compliant
            else f"BAA specifies {baa.breach_notification_hours}-hour breach notification. "
                 f"Updated HIPAA rules require notification within {HIPAA_BREACH_NOTIFICATION_HOURS} hours. "
                 f"BAA amendment required."
        ),
        "severity": "OK" if breach_compliant else "CRITICAL",
    }

    # Contingency notification compliance (24 hours under new HIPAA)
    contingency_compliant = baa.contingency_notification_hours <= HIPAA_CONTINGENCY_NOTIFICATION_HOURS
    checks["contingency_notification_compliant"] = {
        "compliant": contingency_compliant,
        "current_value": f"{baa.contingency_notification_hours} hours",
        "required_value": f"{HIPAA_CONTINGENCY_NOTIFICATION_HOURS} hours",
        "detail": (
            "BAA meets 24-hour contingency plan activation notification requirement"
            if contingency_compliant
            else f"BAA specifies {baa.contingency_notification_hours}-hour contingency notification. "
                 f"Updated HIPAA rules require notification within {HIPAA_CONTINGENCY_NOTIFICATION_HOURS} hours. "
                 f"BAA amendment required."
        ),
        "severity": "OK" if contingency_compliant else "HIGH",
    }

    # Subcontractor flow-down
    checks["subcontractor_flow_down_present"] = {
        "compliant": baa.subcontractor_flow_down,
        "detail": (
            "BAA requires subcontractor compliance with equivalent protections"
            if baa.subcontractor_flow_down
            else "BAA does not include subcontractor flow-down provisions. "
                 "HIPAA requires BAs to ensure subcontractors agree to the same restrictions."
        ),
        "severity": "OK" if baa.subcontractor_flow_down else "HIGH",
    }

    # Expiration status
    if baa.expiration_date is None:
        expiration_status = "NO_EXPIRATION_SET"
        expiration_compliant = False
        expiration_detail = "BAA has no expiration date set. All BAAs should have a defined term."
        expiration_severity = "WARNING"
    elif baa.expiration_date < date.today():
        days_expired = (date.today() - baa.expiration_date).days
        expiration_status = "EXPIRED"
        expiration_compliant = False
        expiration_detail = f"BAA expired {days_expired} days ago on {baa.expiration_date.isoformat()}"
        expiration_severity = "CRITICAL"
    elif (baa.expiration_date - date.today()).days <= 90:
        days_remaining = (baa.expiration_date - date.today()).days
        expiration_status = "EXPIRING_SOON"
        expiration_compliant = True  # Still valid but needs attention
        expiration_detail = f"BAA expires in {days_remaining} days on {baa.expiration_date.isoformat()}"
        expiration_severity = "WARNING"
    else:
        days_remaining = (baa.expiration_date - date.today()).days
        expiration_status = "CURRENT"
        expiration_compliant = True
        expiration_detail = f"BAA is current. Expires in {days_remaining} days on {baa.expiration_date.isoformat()}"
        expiration_severity = "OK"

    checks["expiration_status"] = {
        "compliant": expiration_compliant,
        "status": expiration_status,
        "detail": expiration_detail,
        "severity": expiration_severity,
    }

    # Signature completeness
    signatures_complete = bool(baa.signed_by_vendor and baa.signed_by_org)
    checks["signatures_complete"] = {
        "compliant": signatures_complete,
        "signed_by_vendor": baa.signed_by_vendor or "NOT SIGNED",
        "signed_by_org": baa.signed_by_org or "NOT SIGNED",
        "detail": (
            "BAA is fully executed with signatures from both parties"
            if signatures_complete
            else "BAA is missing one or more required signatures"
        ),
        "severity": "OK" if signatures_complete else "HIGH",
    }

    # Document on file
    has_document = bool(baa.document_path)
    checks["document_on_file"] = {
        "compliant": has_document,
        "document_path": baa.document_path or "NONE",
        "detail": (
            f"BAA document on file: {baa.document_path}"
            if has_document
            else "No BAA document path recorded. A signed copy should be retained."
        ),
        "severity": "OK" if has_document else "WARNING",
    }

    # Overall compliance
    critical_issues = sum(
        1 for c in checks.values() if c.get("severity") == "CRITICAL"
    )
    high_issues = sum(
        1 for c in checks.values() if c.get("severity") == "HIGH"
    )
    warning_issues = sum(
        1 for c in checks.values() if c.get("severity") == "WARNING"
    )

    if critical_issues > 0:
        overall = "NON_COMPLIANT"
    elif high_issues > 0:
        overall = "NEEDS_ATTENTION"
    elif warning_issues > 0:
        overall = "MINOR_ISSUES"
    else:
        overall = "COMPLIANT"

    recommendations = []
    if not breach_compliant:
        recommendations.append(
            "URGENT: Amend BAA to update breach notification timeline to 24 hours "
            "per updated HIPAA Security Rule requirements."
        )
    if not contingency_compliant:
        recommendations.append(
            "Amend BAA to include 24-hour contingency plan activation notification "
            "per updated HIPAA Security Rule requirements."
        )
    if not baa.subcontractor_flow_down:
        recommendations.append(
            "Add subcontractor flow-down provisions requiring all subcontractors "
            "to comply with equivalent security requirements."
        )
    if not signatures_complete:
        recommendations.append(
            "Obtain missing signatures to fully execute the BAA."
        )

    return {
        "baa_id": baa.id,
        "vendor_id": baa.vendor_id,
        "vendor_name": vendor_name,
        "baa_status": baa.status.value,
        "overall_compliance": overall,
        "checks": checks,
        "critical_issues": critical_issues,
        "high_issues": high_issues,
        "warning_issues": warning_issues,
        "recommendations": recommendations,
    }


def get_baa_alerts(db: VendorDatabase) -> List[Dict]:
    """
    Generate actionable alerts for all BAAs requiring attention.

    Identifies:
        - Expired BAAs
        - BAAs expiring soon (within 90 days)
        - Active vendors missing BAAs
        - BAAs with non-compliant notification timelines
        - BAAs missing subcontractor flow-down provisions

    Args:
        db: VendorDatabase instance.

    Returns:
        List of alert dicts sorted by severity.
    """
    alerts: List[Dict] = []
    today = date.today()

    # Check all BAAs for issues
    for baa in db.list_baas():
        vendor = db.get_vendor(baa.vendor_id)
        vendor_name = vendor.name if vendor else "Unknown"

        # Expired BAA
        if baa.status == BAAStatus.ACTIVE and baa.expiration_date and baa.expiration_date < today:
            days_expired = (today - baa.expiration_date).days
            alerts.append({
                "alert_type": "BAA_EXPIRED",
                "severity": "CRITICAL",
                "vendor_id": baa.vendor_id,
                "vendor_name": vendor_name,
                "baa_id": baa.id,
                "message": f"BAA with {vendor_name} expired {days_expired} days ago",
                "action": "Immediately execute a new BAA or terminate vendor relationship",
                "details": {
                    "expiration_date": baa.expiration_date.isoformat(),
                    "days_expired": days_expired,
                },
            })

        # Expiring soon
        elif baa.status == BAAStatus.ACTIVE and baa.expiration_date:
            days_remaining = (baa.expiration_date - today).days
            if days_remaining <= 90:
                alerts.append({
                    "alert_type": "BAA_EXPIRING",
                    "severity": "WARNING" if days_remaining > 30 else "HIGH",
                    "vendor_id": baa.vendor_id,
                    "vendor_name": vendor_name,
                    "baa_id": baa.id,
                    "message": f"BAA with {vendor_name} expires in {days_remaining} days",
                    "action": "Initiate BAA renewal process",
                    "details": {
                        "expiration_date": baa.expiration_date.isoformat(),
                        "days_remaining": days_remaining,
                        "auto_renewal": baa.auto_renewal,
                    },
                })

        # Non-compliant breach notification
        if baa.status == BAAStatus.ACTIVE and baa.breach_notification_hours > HIPAA_BREACH_NOTIFICATION_HOURS:
            alerts.append({
                "alert_type": "BREACH_NOTIFICATION_NON_COMPLIANT",
                "severity": "CRITICAL",
                "vendor_id": baa.vendor_id,
                "vendor_name": vendor_name,
                "baa_id": baa.id,
                "message": (
                    f"BAA with {vendor_name} has {baa.breach_notification_hours}-hour "
                    f"breach notification (24 hours required)"
                ),
                "action": "Amend BAA to require 24-hour breach notification",
                "details": {
                    "current_hours": baa.breach_notification_hours,
                    "required_hours": HIPAA_BREACH_NOTIFICATION_HOURS,
                },
            })

        # Non-compliant contingency notification
        if baa.status == BAAStatus.ACTIVE and baa.contingency_notification_hours > HIPAA_CONTINGENCY_NOTIFICATION_HOURS:
            alerts.append({
                "alert_type": "CONTINGENCY_NOTIFICATION_NON_COMPLIANT",
                "severity": "HIGH",
                "vendor_id": baa.vendor_id,
                "vendor_name": vendor_name,
                "baa_id": baa.id,
                "message": (
                    f"BAA with {vendor_name} has {baa.contingency_notification_hours}-hour "
                    f"contingency notification (24 hours required)"
                ),
                "action": "Amend BAA to require 24-hour contingency plan activation notification",
                "details": {
                    "current_hours": baa.contingency_notification_hours,
                    "required_hours": HIPAA_CONTINGENCY_NOTIFICATION_HOURS,
                },
            })

        # Missing subcontractor flow-down
        if baa.status == BAAStatus.ACTIVE and not baa.subcontractor_flow_down:
            alerts.append({
                "alert_type": "MISSING_FLOW_DOWN",
                "severity": "HIGH",
                "vendor_id": baa.vendor_id,
                "vendor_name": vendor_name,
                "baa_id": baa.id,
                "message": f"BAA with {vendor_name} lacks subcontractor flow-down provisions",
                "action": "Amend BAA to include subcontractor compliance requirements",
            })

    # Check for active vendors without ANY BAA
    for vendor in db.list_vendors():
        if vendor.status not in (VendorStatus.ACTIVE, VendorStatus.UNDER_REVIEW):
            continue
        if not vendor.phi_access:
            continue

        vendor_baas = db.list_baas(vendor_id=vendor.id)
        active_baas = [b for b in vendor_baas if b.status == BAAStatus.ACTIVE]

        if not active_baas:
            alerts.append({
                "alert_type": "MISSING_BAA",
                "severity": "CRITICAL",
                "vendor_id": vendor.id,
                "vendor_name": vendor.name,
                "baa_id": None,
                "message": f"Active vendor {vendor.name} with PHI access has no active BAA",
                "action": "Execute BAA immediately — PHI access without BAA violates HIPAA",
            })

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "NOTICE": 3}
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 99))

    return alerts


def renew_baa(
    baa_id: str,
    new_expiration: date,
    db: VendorDatabase,
    new_terms: Optional[Dict] = None,
) -> BAA:
    """
    Renew an existing BAA with updated expiration and optional term changes.

    If new_terms includes updated notification hours or subcontractor
    flow-down, those are applied to bring the BAA into compliance.

    Args:
        baa_id: UUID of the BAA to renew.
        new_expiration: New expiration date.
        db: VendorDatabase instance.
        new_terms: Optional dict of terms to update during renewal.

    Returns:
        Updated BAA instance.

    Raises:
        ValueError: If BAA not found.
    """
    baa = db.get_baa(baa_id)
    if baa is None:
        raise ValueError(f"BAA '{baa_id}' not found")

    old_expiration = baa.expiration_date

    # Update expiration
    baa.expiration_date = new_expiration
    baa.status = BAAStatus.ACTIVE
    baa.last_updated_date = date.today()
    baa.updated_at = datetime.now()

    # Apply new terms if provided
    if new_terms:
        if "version" in new_terms:
            baa.version = new_terms["version"]
        if "breach_notification_hours" in new_terms:
            baa.breach_notification_hours = new_terms["breach_notification_hours"]
        if "contingency_notification_hours" in new_terms:
            baa.contingency_notification_hours = new_terms["contingency_notification_hours"]
        if "subcontractor_flow_down" in new_terms:
            baa.subcontractor_flow_down = new_terms["subcontractor_flow_down"]
        if "signed_by_vendor" in new_terms:
            baa.signed_by_vendor = new_terms["signed_by_vendor"]
        if "signed_by_org" in new_terms:
            baa.signed_by_org = new_terms["signed_by_org"]
        if "document_path" in new_terms:
            baa.document_path = new_terms["document_path"]
        if "terms" in new_terms:
            baa.terms = new_terms["terms"]

    baa.notes.append(
        f"[{datetime.now().isoformat()}] BAA renewed. "
        f"Previous expiration: {old_expiration.isoformat() if old_expiration else 'None'}. "
        f"New expiration: {new_expiration.isoformat()}"
    )

    return db.save_baa(baa)


def get_baa_summary(db: VendorDatabase) -> Dict:
    """
    Generate an organization-wide BAA summary report.

    Args:
        db: VendorDatabase instance.

    Returns:
        Dict with BAA statistics and status breakdown.
    """
    all_baas = db.list_baas()
    today = date.today()

    status_counts = {}
    for baa in all_baas:
        status = baa.status.value
        status_counts[status] = status_counts.get(status, 0) + 1

    active_baas = [b for b in all_baas if b.status == BAAStatus.ACTIVE]
    compliant_count = 0
    non_compliant_count = 0

    for baa in active_baas:
        if (baa.breach_notification_hours <= HIPAA_BREACH_NOTIFICATION_HOURS
                and baa.contingency_notification_hours <= HIPAA_CONTINGENCY_NOTIFICATION_HOURS
                and baa.subcontractor_flow_down):
            compliant_count += 1
        else:
            non_compliant_count += 1

    expiring_30 = sum(
        1 for b in active_baas
        if b.expiration_date and 0 < (b.expiration_date - today).days <= 30
    )
    expiring_90 = sum(
        1 for b in active_baas
        if b.expiration_date and 0 < (b.expiration_date - today).days <= 90
    )
    expired = sum(
        1 for b in active_baas
        if b.expiration_date and b.expiration_date < today
    )

    return {
        "total_baas": len(all_baas),
        "status_breakdown": status_counts,
        "active_baas": len(active_baas),
        "fully_compliant": compliant_count,
        "needs_amendment": non_compliant_count,
        "expiring_within_30_days": expiring_30,
        "expiring_within_90_days": expiring_90,
        "expired": expired,
    }
