"""
Multi-dimensional risk scoring engine for Vendor Risk Manager.

Computes three risk dimensions:
    1. Inherent Risk Score — based on vendor characteristics (PHI access,
       data volume, integration types, vendor criticality)
    2. Control Effectiveness Score — derived from assessment responses
       against the HIPAA/NIST/HITRUST control library
    3. Residual Risk Score — inherent risk modulated by control effectiveness

Also provides:
    - Domain-level scoring breakdowns
    - Automatic vendor tier classification
    - Risk trend analysis (IMPROVING / STABLE / DECLINING)

VerifAI Security | Created by Nathan Mills
"""

from typing import Dict, List, Optional, Tuple

from .models import (
    Answer,
    AssessmentResponse,
    DataVolume,
    FindingSeverity,
    RiskScore,
    Vendor,
    VendorAssessment,
    VendorTier,
    VendorType,
    SENSITIVE_PHI_TYPES,
    CLINICAL_INTEGRATION_TYPES,
)
from .controls import AssessmentQuestion, CONTROL_INDEX, DOMAINS


# ============================================================================
# Inherent Risk Scoring Configuration
# ============================================================================

# Points for PHI access
PHI_ACCESS_POINTS = 40

# Points per PHI type
PHI_TYPE_SENSITIVE_POINTS = 10   # genetic, mental_health, substance_abuse, hiv_aids
PHI_TYPE_STANDARD_POINTS = 5    # demographics, diagnoses, medications, etc.

# Points for data volume
DATA_VOLUME_POINTS: Dict[DataVolume, int] = {
    DataVolume.HIGH: 20,
    DataVolume.MEDIUM: 10,
    DataVolume.LOW: 5,
    DataVolume.NONE: 0,
}

# Points for integration types
CLINICAL_INTEGRATION_POINTS = 10   # HL7, FHIR, DICOM
TECHNICAL_INTEGRATION_POINTS = 5   # API, VPN
BASIC_INTEGRATION_POINTS = 3       # Web Portal, SFTP

INTEGRATION_POINTS_MAP: Dict[str, int] = {
    "HL7": CLINICAL_INTEGRATION_POINTS,
    "FHIR": CLINICAL_INTEGRATION_POINTS,
    "DICOM": CLINICAL_INTEGRATION_POINTS,
    "API": TECHNICAL_INTEGRATION_POINTS,
    "VPN": TECHNICAL_INTEGRATION_POINTS,
    "Direct": TECHNICAL_INTEGRATION_POINTS,
    "WEB_PORTAL": BASIC_INTEGRATION_POINTS,
    "SFTP": BASIC_INTEGRATION_POINTS,
    "OTHER": BASIC_INTEGRATION_POINTS,
}

# Points for vendor type criticality
VENDOR_TYPE_CRITICALITY: Dict[VendorType, int] = {
    VendorType.EHR_PROVIDER: 15,
    VendorType.CLOUD_SERVICE: 15,
    VendorType.BILLING_SERVICE: 10,
    VendorType.CLEARINGHOUSE: 10,
    VendorType.TELEHEALTH: 10,
    VendorType.LAB_SYSTEM: 10,
    VendorType.PHARMACY_SYSTEM: 10,
    VendorType.IT_MANAGED_SERVICE: 8,
    VendorType.IMAGING: 8,
    VendorType.MEDICAL_DEVICE_MFG: 8,
    VendorType.TRANSCRIPTION: 5,
    VendorType.DESTRUCTION_SERVICE: 5,
    VendorType.INSURANCE: 5,
    VendorType.CONSULTING: 3,
    VendorType.OTHER: 3,
}

# Maximum raw inherent score (for normalization)
# PHI(40) + sensitive PHI types 4*10(40) + standard PHI types 7*5(35) + HIGH volume(20) +
# multiple integrations ~30 + vendor type(15) ≈ 180
MAX_RAW_INHERENT = 180


# ============================================================================
# Control Effectiveness Scoring
# ============================================================================

# Penalty multipliers per answer type
ANSWER_PENALTIES: Dict[Answer, float] = {
    Answer.YES: 0.0,
    Answer.PARTIAL: 0.4,
    Answer.NO: 1.0,
    Answer.UNKNOWN: 0.7,
    Answer.NOT_APPLICABLE: 0.0,  # Excluded from scoring
}


# ============================================================================
# Tier Classification Thresholds
# ============================================================================

CRITICAL_THRESHOLD = 70
HIGH_THRESHOLD = 50
MEDIUM_THRESHOLD = 30

# Trend detection threshold (points change)
TREND_THRESHOLD = 5.0


# ============================================================================
# Scoring Functions
# ============================================================================

def calculate_inherent_risk(vendor: Vendor) -> float:
    """
    Calculate inherent risk score based on vendor characteristics.

    Inherent risk represents the baseline risk level before any controls
    are considered. Based on PHI access, data sensitivity, volume,
    integration complexity, and vendor type criticality.

    Args:
        vendor: The Vendor to score.

    Returns:
        Normalized inherent risk score from 0.0 (no risk) to 100.0 (maximum risk).
    """
    raw_score = 0.0

    # PHI access
    if vendor.phi_access:
        raw_score += PHI_ACCESS_POINTS

    # PHI types sensitivity
    for phi_type in vendor.phi_types:
        if phi_type in SENSITIVE_PHI_TYPES:
            raw_score += PHI_TYPE_SENSITIVE_POINTS
        else:
            raw_score += PHI_TYPE_STANDARD_POINTS

    # Data volume
    raw_score += DATA_VOLUME_POINTS.get(vendor.data_volume, 0)

    # Integration types (take highest-risk integration)
    max_integration_points = 0
    for itype in vendor.integration_type:
        points = INTEGRATION_POINTS_MAP.get(itype, BASIC_INTEGRATION_POINTS)
        if points > max_integration_points:
            max_integration_points = points
    raw_score += max_integration_points

    # Additional points for multiple clinical integrations
    clinical_count = sum(
        1 for itype in vendor.integration_type
        if itype in CLINICAL_INTEGRATION_TYPES
    )
    if clinical_count > 1:
        raw_score += (clinical_count - 1) * 5

    # Vendor type criticality
    raw_score += VENDOR_TYPE_CRITICALITY.get(vendor.vendor_type, 3)

    # Normalize to 0-100
    normalized = min(100.0, (raw_score / MAX_RAW_INHERENT) * 100.0)
    return round(normalized, 1)


def calculate_control_effectiveness(
    responses: Dict[str, AssessmentResponse],
    questions: Optional[List[AssessmentQuestion]] = None,
) -> Tuple[float, Dict[str, float]]:
    """
    Calculate control effectiveness score from assessment responses.

    For each response, a penalty is calculated based on the answer type
    and the question's weight. The overall score represents how effectively
    controls mitigate the inherent risk.

    Args:
        responses: Dict mapping question_id to AssessmentResponse.
        questions: Optional list of questions to score against. If None,
                   uses the full control library via CONTROL_INDEX.

    Returns:
        Tuple of (overall_score, domain_scores) where scores range from
        0.0 (no controls) to 100.0 (fully compliant).
    """
    domain_penalties: Dict[str, float] = {}
    domain_weights: Dict[str, float] = {}

    for question_id, response in responses.items():
        # Look up the question
        question = None
        if questions:
            for q in questions:
                if q.id == question_id:
                    question = q
                    break
        if question is None:
            question = CONTROL_INDEX.get(question_id)
        if question is None:
            continue

        # Skip N/A responses
        if response.answer == Answer.NOT_APPLICABLE:
            continue

        domain = question.domain
        penalty = ANSWER_PENALTIES.get(response.answer, 0.7) * question.weight

        domain_penalties[domain] = domain_penalties.get(domain, 0.0) + penalty
        domain_weights[domain] = domain_weights.get(domain, 0.0) + question.weight

    # Calculate domain scores
    domain_scores: Dict[str, float] = {}
    total_penalty = 0.0
    total_weight = 0.0

    for domain in DOMAINS:
        weight = domain_weights.get(domain, 0.0)
        penalty = domain_penalties.get(domain, 0.0)
        if weight > 0:
            domain_score = max(0.0, 100.0 * (1.0 - penalty / weight))
            domain_scores[domain] = round(domain_score, 1)
            total_penalty += penalty
            total_weight += weight
        else:
            # No questions answered for this domain
            domain_scores[domain] = 0.0

    # Calculate overall score
    if total_weight > 0:
        overall = max(0.0, 100.0 * (1.0 - total_penalty / total_weight))
    else:
        overall = 0.0

    return round(overall, 1), domain_scores


def calculate_residual_risk(
    inherent_risk: float,
    control_effectiveness: float,
) -> float:
    """
    Calculate residual risk from inherent risk and control effectiveness.

    Formula: residual = inherent_risk * (1 - control_effectiveness / 100)

    A high inherent risk vendor with strong controls will have low residual
    risk. A low inherent risk vendor with weak controls will have moderate
    residual risk.

    Args:
        inherent_risk: Score from 0-100 (higher = more inherent risk).
        control_effectiveness: Score from 0-100 (higher = better controls).

    Returns:
        Residual risk score from 0.0 to 100.0.
    """
    residual = inherent_risk * (1.0 - control_effectiveness / 100.0)
    return round(min(100.0, max(0.0, residual)), 1)


def classify_vendor_tier(
    residual_risk: float,
    domain_scores: Dict[str, float],
    has_critical_findings: bool = False,
    phi_access: bool = False,
    control_effectiveness: float = 100.0,
) -> VendorTier:
    """
    Automatically classify a vendor's risk tier based on residual risk.

    Classification rules:
        - CRITICAL: residual >= 70, or any CRITICAL findings, or PHI access with score < 50
        - HIGH: residual >= 50, or any domain score < 40
        - MEDIUM: residual >= 30
        - LOW: residual < 30

    Args:
        residual_risk: The calculated residual risk score.
        domain_scores: Dict of domain name to domain score.
        has_critical_findings: Whether any CRITICAL severity findings exist.
        phi_access: Whether the vendor has PHI access.
        control_effectiveness: Overall control effectiveness score.

    Returns:
        VendorTier classification.
    """
    # CRITICAL conditions
    if residual_risk >= CRITICAL_THRESHOLD:
        return VendorTier.CRITICAL
    if has_critical_findings:
        return VendorTier.CRITICAL
    if phi_access and control_effectiveness < 50:
        return VendorTier.CRITICAL

    # HIGH conditions
    if residual_risk >= HIGH_THRESHOLD:
        return VendorTier.HIGH
    # Any domain scoring below 40 is HIGH risk
    for domain, score in domain_scores.items():
        if score > 0 and score < 40:
            return VendorTier.HIGH

    # MEDIUM
    if residual_risk >= MEDIUM_THRESHOLD:
        return VendorTier.MEDIUM

    # LOW
    return VendorTier.LOW


def calculate_risk_trend(
    current_score: float,
    previous_score: Optional[float],
) -> str:
    """
    Determine risk trend by comparing current and previous assessment scores.

    Args:
        current_score: Current control effectiveness score (0-100).
        previous_score: Previous control effectiveness score, or None.

    Returns:
        "IMPROVING" if score improved by 5+, "DECLINING" if dropped by 5+,
        "STABLE" otherwise or if no previous score available.
    """
    if previous_score is None:
        return "STABLE"

    delta = current_score - previous_score
    if delta >= TREND_THRESHOLD:
        return "IMPROVING"
    elif delta <= -TREND_THRESHOLD:
        return "DECLINING"
    return "STABLE"


def calculate_risk_score(
    vendor: Vendor,
    assessment: VendorAssessment,
    previous_assessment: Optional[VendorAssessment] = None,
    questions: Optional[List[AssessmentQuestion]] = None,
) -> RiskScore:
    """
    Calculate a comprehensive risk score for a vendor.

    Combines inherent risk, control effectiveness, and residual risk into
    a single RiskScore object with domain breakdowns and trend analysis.

    Args:
        vendor: The Vendor being assessed.
        assessment: The current VendorAssessment with responses.
        previous_assessment: Optional previous assessment for trend calculation.
        questions: Optional question list (defaults to control library).

    Returns:
        Fully populated RiskScore instance.
    """
    # Step 1: Inherent risk
    inherent = calculate_inherent_risk(vendor)

    # Step 2: Control effectiveness
    effectiveness, domain_scores = calculate_control_effectiveness(
        assessment.responses, questions
    )

    # Step 3: Residual risk
    residual = calculate_residual_risk(inherent, effectiveness)

    # Step 4: Check for critical findings
    has_critical = any(
        f.severity == FindingSeverity.CRITICAL
        for f in assessment.findings
    )

    # Step 5: Classify tier
    tier = classify_vendor_tier(
        residual_risk=residual,
        domain_scores=domain_scores,
        has_critical_findings=has_critical,
        phi_access=vendor.phi_access,
        control_effectiveness=effectiveness,
    )

    # Step 6: Calculate trend
    previous_score = None
    if previous_assessment and previous_assessment.overall_score > 0:
        previous_score = previous_assessment.overall_score
    trend = calculate_risk_trend(effectiveness, previous_score)

    return RiskScore(
        vendor_id=vendor.id,
        overall_score=effectiveness,
        risk_level=tier.value.upper(),
        domain_scores=domain_scores,
        inherent_risk_score=inherent,
        residual_risk_score=residual,
        trend=trend,
    )


def get_risk_level_label(tier: VendorTier) -> str:
    """
    Get a human-readable label for a risk tier.

    Args:
        tier: VendorTier enum value.

    Returns:
        Formatted string like "CRITICAL RISK" or "LOW RISK".
    """
    labels = {
        VendorTier.CRITICAL: "CRITICAL RISK",
        VendorTier.HIGH: "HIGH RISK",
        VendorTier.MEDIUM: "MEDIUM RISK",
        VendorTier.LOW: "LOW RISK",
    }
    return labels.get(tier, "UNKNOWN")


def get_tier_recommendations(tier: VendorTier) -> List[str]:
    """
    Get recommended actions based on vendor risk tier.

    Args:
        tier: VendorTier classification.

    Returns:
        List of recommended action strings.
    """
    recommendations = {
        VendorTier.CRITICAL: [
            "Immediate executive review required",
            "Consider suspending vendor access until critical findings are remediated",
            "Require corrective action plan within 30 days",
            "Increase monitoring to continuous",
            "Escalate to HIPAA Security Official and legal counsel",
            "Evaluate alternative vendors",
        ],
        VendorTier.HIGH: [
            "Quarterly reassessment required",
            "Require corrective action plan within 60 days",
            "Enhanced monitoring of vendor activities",
            "Review BAA terms for adequacy",
            "Consider additional contractual safeguards",
        ],
        VendorTier.MEDIUM: [
            "Semi-annual reassessment recommended",
            "Address findings per standard remediation timelines",
            "Monitor vendor's security posture for changes",
            "Ensure BAA is current and compliant",
        ],
        VendorTier.LOW: [
            "Annual reassessment per standard schedule",
            "Maintain current BAA and verification",
            "Address any findings per standard timelines",
        ],
    }
    return recommendations.get(tier, [])
