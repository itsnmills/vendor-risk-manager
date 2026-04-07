"""
Assessment orchestration engine for Vendor Risk Manager.

Runs vendor security assessments by scoring responses against the
HIPAA/NIST/HITRUST control library, generating findings with specific
remediation recommendations, identifying strengths, and producing
a fully populated VendorAssessment with domain-level scoring.

VerifAI Security | Created by Nathan Mills
"""

from datetime import date, datetime, timedelta
from typing import Dict, List, Optional

from .models import (
    Answer,
    AssessmentResponse,
    AssessmentStatus,
    AssessmentType,
    Finding,
    FindingSeverity,
    FindingStatus,
    RemediationTimeline,
    Vendor,
    VendorAssessment,
    VendorTier,
)
from .controls import (
    AssessmentQuestion,
    CONTROL_INDEX,
    CONTROL_LIBRARY,
    DOMAINS,
    get_questions_for_vendor,
)
from .scoring import (
    calculate_control_effectiveness,
    calculate_inherent_risk,
    calculate_residual_risk,
    calculate_risk_score,
    classify_vendor_tier,
    get_risk_level_label,
)
from .db import VendorDatabase


# ============================================================================
# Remediation Recommendations by Domain
# ============================================================================

RECOMMENDATIONS: Dict[str, Dict[str, str]] = {
    "Access Control & Authentication": {
        "NO": (
            "Implement role-based access controls (RBAC) with unique user IDs, "
            "enforce multi-factor authentication (MFA) for all ePHI systems, "
            "and establish formal access provisioning/de-provisioning procedures. "
            "Conduct quarterly access reviews and ensure automatic logoff is "
            "configured for all sessions. Reference NIST SP 800-63B for "
            "authentication assurance levels."
        ),
        "PARTIAL": (
            "Enhance existing access controls by closing identified gaps. "
            "Ensure MFA is enforced consistently across all ePHI-accessible "
            "systems (not just some). Strengthen access review processes to "
            "cover all accounts including service accounts and API keys. "
            "Document and test emergency access procedures."
        ),
        "UNKNOWN": (
            "Conduct an immediate audit of all access control mechanisms. "
            "Document current authentication and authorization practices. "
            "The inability to confirm access control status represents a "
            "significant compliance gap that must be resolved urgently."
        ),
    },
    "Encryption & Data Protection": {
        "NO": (
            "Deploy AES-256 encryption for all ePHI at rest and TLS 1.2+ "
            "for all data in transit. Implement a formal key management "
            "program covering key generation, distribution, rotation, and "
            "destruction. Deploy DLP controls to prevent unauthorized ePHI "
            "transmission. Ensure all backups and portable media are encrypted. "
            "Reference NIST SP 800-111 for storage encryption guidance."
        ),
        "PARTIAL": (
            "Expand encryption coverage to include all identified gaps. "
            "Upgrade any systems using TLS 1.0/1.1 to TLS 1.2+. "
            "Formalize key rotation schedules and document key management "
            "procedures. Implement data masking for non-production environments."
        ),
        "UNKNOWN": (
            "Perform a comprehensive data flow analysis to map all locations "
            "where ePHI is stored, processed, and transmitted. Verify "
            "encryption status at each point. The inability to confirm "
            "encryption status must be treated as a potential exposure risk."
        ),
    },
    "Audit & Monitoring": {
        "NO": (
            "Implement comprehensive audit logging for all systems processing "
            "ePHI, including user ID, timestamp, action, and affected records. "
            "Deploy centralized log management (SIEM) with real-time alerting "
            "for critical events. Establish a 6-year log retention policy. "
            "Implement log integrity controls (immutable storage or hashing). "
            "Deploy EDR on all endpoints."
        ),
        "PARTIAL": (
            "Extend audit logging coverage to all ePHI systems. Enhance "
            "alert rules to cover suspicious access patterns, privilege "
            "escalation, and bulk data access. Formalize log review "
            "procedures with documented schedules and responsibilities."
        ),
        "UNKNOWN": (
            "Urgently assess current audit capabilities. Without confirmed "
            "audit trails, breach detection and forensic investigation are "
            "severely impaired. Prioritize deploying basic logging immediately "
            "while planning comprehensive SIEM deployment."
        ),
    },
    "Incident Response & Breach Notification": {
        "NO": (
            "Develop and document a comprehensive incident response plan "
            "addressing ePHI breaches. Ensure 24-hour breach notification "
            "capability as required by updated HIPAA rules. Establish "
            "relationships with digital forensics providers. Create "
            "communication templates for breach notification. Conduct "
            "initial tabletop exercise within 90 days."
        ),
        "PARTIAL": (
            "Update IR plan to address gaps, particularly the new 24-hour "
            "notification requirement. Expand tabletop exercises to include "
            "ransomware and supply chain scenarios. Formalize post-incident "
            "review procedures and evidence preservation processes."
        ),
        "UNKNOWN": (
            "The inability to confirm incident response readiness is a "
            "critical risk. Immediately assess current IR capabilities "
            "and develop a plan. Prioritize establishing basic notification "
            "procedures and contact lists as an interim measure."
        ),
    },
    "Business Continuity & Disaster Recovery": {
        "NO": (
            "Develop business continuity and disaster recovery plans for "
            "all systems processing ePHI. Define RPO/RTO objectives. "
            "Implement encrypted backup procedures with regular testing. "
            "Establish 24-hour contingency plan activation notification "
            "per updated HIPAA requirements. Plan annual DR testing."
        ),
        "PARTIAL": (
            "Address gaps in existing BCP/DR plans. Ensure RPO/RTO "
            "objectives are formally documented and achievable. Increase "
            "backup testing frequency. Verify geographic redundancy for "
            "critical ePHI systems. Update notification procedures for "
            "24-hour contingency plan activation requirement."
        ),
        "UNKNOWN": (
            "Assess current backup and recovery capabilities immediately. "
            "Unknown continuity posture presents significant risk to ePHI "
            "availability. At minimum, verify that backups exist and can "
            "be successfully restored."
        ),
    },
    "Physical & Environmental Security": {
        "NO": (
            "Implement physical access controls (badge readers, visitor "
            "logging) for all facilities housing ePHI systems. Deploy "
            "environmental controls (fire suppression, HVAC, UPS). "
            "Establish media disposal procedures following NIST 800-88. "
            "Create and maintain a complete hardware asset inventory."
        ),
        "PARTIAL": (
            "Strengthen existing physical controls by addressing identified "
            "gaps. Ensure media disposal procedures are consistently followed "
            "with documentation. Update hardware inventory to capture all "
            "ePHI-processing assets. Enhance visitor management procedures."
        ),
        "UNKNOWN": (
            "Conduct a physical security assessment of all facilities. "
            "Unknown physical security status could indicate undetected "
            "physical access vulnerabilities affecting ePHI systems."
        ),
    },
    "Vendor & Subcontractor Management": {
        "NO": (
            "Establish a subcontractor management program requiring BAAs "
            "with all subcontractors accessing ePHI. Create and maintain "
            "an inventory of all fourth parties with ePHI access. Implement "
            "subcontractor security assessments and ongoing monitoring. "
            "Develop termination procedures ensuring ePHI return/destruction."
        ),
        "PARTIAL": (
            "Complete the subcontractor inventory and ensure BAA flow-down "
            "to all ePHI-accessing subcontractors. Strengthen notification "
            "requirements for new subcontractor onboarding. Enhance "
            "monitoring of existing subcontractor security posture."
        ),
        "UNKNOWN": (
            "Immediately inventory all subcontractors with ePHI access. "
            "Unknown subcontractor management status creates significant "
            "supply chain risk. Verify BAA status with all known "
            "subcontractors as a priority action."
        ),
    },
    "Workforce Security & Training": {
        "NO": (
            "Implement background checks for all employees with ePHI access. "
            "Develop and deliver annual HIPAA security awareness training. "
            "Create role-based training programs for technical staff. "
            "Establish termination procedures with immediate access revocation. "
            "Implement confidentiality agreements and sanctions policy."
        ),
        "PARTIAL": (
            "Expand training coverage to all workforce members. Enhance "
            "training content to address identified gaps. Strengthen "
            "termination procedures to ensure timely access revocation. "
            "Begin phishing simulation exercises to test awareness."
        ),
        "UNKNOWN": (
            "Assess current workforce security practices immediately. "
            "Unknown training and background check status could indicate "
            "unauthorized access to ePHI by unvetted personnel."
        ),
    },
    "Vulnerability Management": {
        "NO": (
            "Implement vulnerability scanning at least semi-annually and "
            "annual penetration testing as required by updated HIPAA rules. "
            "Establish a patch management program with defined SLAs "
            "(critical: 14 days, high: 30 days). Create remediation "
            "tracking procedures. Address end-of-life software/hardware. "
            "Begin maintaining SBOM for ePHI applications."
        ),
        "PARTIAL": (
            "Increase scanning frequency to meet the semi-annual HIPAA "
            "requirement. Ensure penetration testing covers all ePHI "
            "systems. Tighten patch management SLAs and improve "
            "remediation tracking. Address web application security "
            "testing gaps (OWASP Top 10)."
        ),
        "UNKNOWN": (
            "Unknown vulnerability management status is a critical risk. "
            "Immediately conduct a vulnerability scan of all ePHI systems "
            "and prioritize remediation of critical/high findings. "
            "Establish basic patch management procedures."
        ),
    },
    "Network Security & Segmentation": {
        "NO": (
            "Implement network segmentation to isolate ePHI systems as "
            "required by updated HIPAA rules. Deploy and configure "
            "firewalls with deny-all-by-default policies. Implement "
            "IDS/IPS for ePHI network segments. Secure remote access "
            "with VPN/zero-trust and MFA. Document network architecture "
            "with data flow diagrams."
        ),
        "PARTIAL": (
            "Strengthen network segmentation to ensure complete isolation "
            "of ePHI systems. Review and harden firewall rules. Enhance "
            "outbound traffic monitoring to detect potential exfiltration. "
            "Update network documentation to reflect current architecture."
        ),
        "UNKNOWN": (
            "Conduct an immediate network architecture review. Unknown "
            "network security status could indicate ePHI exposure on "
            "unsegmented networks. Prioritize network discovery and "
            "segmentation assessment."
        ),
    },
}


# ============================================================================
# Severity Classification
# ============================================================================

def _classify_finding_severity(
    question: AssessmentQuestion,
    answer: Answer,
) -> FindingSeverity:
    """
    Determine finding severity based on question properties and answer.

    Args:
        question: The assessment question that was not fully met.
        answer: The vendor's response.

    Returns:
        FindingSeverity classification.
    """
    # Critical questions with NO answer are CRITICAL findings
    if question.is_critical and answer == Answer.NO:
        return FindingSeverity.CRITICAL

    # Critical questions with UNKNOWN are HIGH
    if question.is_critical and answer == Answer.UNKNOWN:
        return FindingSeverity.HIGH

    # High-weight questions (2.0+) with NO are HIGH
    if question.weight >= 2.0 and answer == Answer.NO:
        return FindingSeverity.HIGH

    # High-weight questions with PARTIAL/UNKNOWN are MEDIUM
    if question.weight >= 2.0 and answer in (Answer.PARTIAL, Answer.UNKNOWN):
        return FindingSeverity.MEDIUM

    # NO answers on standard questions are MEDIUM
    if answer == Answer.NO:
        return FindingSeverity.MEDIUM

    # Everything else (PARTIAL/UNKNOWN on standard questions) is LOW
    return FindingSeverity.LOW


def _get_remediation_timeline(severity: FindingSeverity) -> RemediationTimeline:
    """
    Map finding severity to a remediation timeline.

    Args:
        severity: The finding's severity level.

    Returns:
        Appropriate RemediationTimeline.
    """
    timelines = {
        FindingSeverity.CRITICAL: RemediationTimeline.IMMEDIATE,
        FindingSeverity.HIGH: RemediationTimeline.DAYS_30,
        FindingSeverity.MEDIUM: RemediationTimeline.DAYS_60,
        FindingSeverity.LOW: RemediationTimeline.DAYS_90,
    }
    return timelines.get(severity, RemediationTimeline.DAYS_90)


def _calculate_due_date(timeline: RemediationTimeline) -> date:
    """
    Calculate a due date based on remediation timeline.

    Args:
        timeline: The remediation timeline.

    Returns:
        Calculated due date.
    """
    days_map = {
        RemediationTimeline.IMMEDIATE: 7,  # 7 days for "immediate"
        RemediationTimeline.DAYS_30: 30,
        RemediationTimeline.DAYS_60: 60,
        RemediationTimeline.DAYS_90: 90,
        RemediationTimeline.DAYS_180: 180,
    }
    days = days_map.get(timeline, 90)
    return date.today() + timedelta(days=days)


def _get_recommendation_text(domain: str, answer: Answer) -> str:
    """
    Get domain-specific remediation recommendation text.

    Args:
        domain: The control domain name.
        answer: The vendor's answer type.

    Returns:
        Recommendation text string.
    """
    domain_recs = RECOMMENDATIONS.get(domain, {})
    if answer == Answer.NO:
        return domain_recs.get("NO", "Implement required controls for this domain.")
    elif answer == Answer.PARTIAL:
        return domain_recs.get("PARTIAL", "Address gaps in existing controls for this domain.")
    elif answer == Answer.UNKNOWN:
        return domain_recs.get("UNKNOWN", "Assess and document current control status for this domain.")
    return "Review and strengthen controls in this domain."


# ============================================================================
# Assessment Engine
# ============================================================================

def run_assessment(
    vendor: Vendor,
    assessment_type: AssessmentType,
    responses: Dict[str, AssessmentResponse],
    assessed_by: str = "",
    db: Optional[VendorDatabase] = None,
) -> VendorAssessment:
    """
    Run a complete vendor security assessment.

    Scores all responses against the control library, generates findings
    for non-compliant answers, identifies strengths, calculates domain
    and overall scores, and auto-classifies the vendor's risk tier.

    Args:
        vendor: The Vendor being assessed.
        assessment_type: Type of assessment being conducted.
        responses: Dict mapping question_id to AssessmentResponse.
        assessed_by: Name/ID of the assessor.
        db: Optional VendorDatabase for looking up previous assessments.

    Returns:
        Fully populated VendorAssessment with scores, findings, and strengths.
    """
    # Get applicable questions for this vendor
    applicable_questions = get_questions_for_vendor(vendor.vendor_type, vendor.phi_access)
    applicable_ids = {q.id for q in applicable_questions}

    # Filter responses to only applicable questions
    valid_responses = {
        qid: resp for qid, resp in responses.items()
        if qid in applicable_ids
    }

    # Calculate scores
    effectiveness, domain_scores = calculate_control_effectiveness(
        valid_responses, applicable_questions
    )
    inherent = calculate_inherent_risk(vendor)
    residual = calculate_residual_risk(inherent, effectiveness)

    # Generate findings for non-compliant responses
    findings: List[Finding] = []
    domain_non_compliant: Dict[str, List[str]] = {d: [] for d in DOMAINS}

    for question_id, response in valid_responses.items():
        if response.answer in (Answer.YES, Answer.NOT_APPLICABLE):
            continue

        question = CONTROL_INDEX.get(question_id)
        if question is None:
            continue

        severity = _classify_finding_severity(question, response.answer)
        timeline = _get_remediation_timeline(severity)
        recommendation = _get_recommendation_text(question.domain, response.answer)

        finding = Finding(
            vendor_id=vendor.id,
            assessment_id="",  # Will be set after assessment is created
            severity=severity,
            domain=question.domain,
            title=f"{question.subdomain}: {_answer_label(response.answer)}",
            description=(
                f"Assessment question {question.id} ({question.subdomain}): "
                f"\"{question.question_text}\" — Vendor response: {response.answer.value.upper()}. "
                f"HIPAA reference: {question.hipaa_reference}. "
                f"NIST CSF: {question.nist_csf_reference}. "
                f"HITRUST: {question.hitrust_reference}."
            ),
            hipaa_reference=question.hipaa_reference,
            nist_reference=question.nist_csf_reference,
            recommendation=recommendation,
            remediation_timeline=timeline,
            status=FindingStatus.OPEN,
            due_date=_calculate_due_date(timeline),
        )
        findings.append(finding)
        domain_non_compliant[question.domain].append(question_id)

    # Identify strengths (domains where all answered controls are compliant)
    strengths: List[str] = []
    domain_questions: Dict[str, int] = {}
    domain_compliant: Dict[str, int] = {}

    for question_id, response in valid_responses.items():
        question = CONTROL_INDEX.get(question_id)
        if question is None:
            continue
        if response.answer == Answer.NOT_APPLICABLE:
            continue

        domain = question.domain
        domain_questions[domain] = domain_questions.get(domain, 0) + 1
        if response.answer == Answer.YES:
            domain_compliant[domain] = domain_compliant.get(domain, 0) + 1

    for domain in DOMAINS:
        total = domain_questions.get(domain, 0)
        compliant = domain_compliant.get(domain, 0)
        if total > 0 and compliant == total:
            strengths.append(
                f"{domain}: All {total} applicable controls fully implemented"
            )
        elif total > 0 and compliant >= total * 0.9:
            strengths.append(
                f"{domain}: Strong compliance ({compliant}/{total} controls met)"
            )

    # Check for critical findings
    has_critical = any(f.severity == FindingSeverity.CRITICAL for f in findings)

    # Classify tier
    tier = classify_vendor_tier(
        residual_risk=residual,
        domain_scores=domain_scores,
        has_critical_findings=has_critical,
        phi_access=vendor.phi_access,
        control_effectiveness=effectiveness,
    )

    # Get previous assessment for trend
    previous_assessment = None
    if db:
        past = db.list_assessments(vendor_id=vendor.id)
        completed_past = [
            a for a in past
            if a.status == AssessmentStatus.COMPLETED and a.overall_score > 0
        ]
        if completed_past:
            previous_assessment = completed_past[-1]

    # Determine next due date
    if assessment_type == AssessmentType.INITIAL:
        next_due = date.today() + timedelta(days=365)
    elif assessment_type == AssessmentType.ANNUAL:
        next_due = date.today() + timedelta(days=365)
    elif assessment_type == AssessmentType.TRIGGERED:
        next_due = date.today() + timedelta(days=180)
    else:
        next_due = date.today() + timedelta(days=365)

    # Adjust next due based on tier
    if tier in (VendorTier.CRITICAL, VendorTier.HIGH):
        next_due = date.today() + timedelta(days=90)

    # Build the assessment
    assessment = VendorAssessment(
        vendor_id=vendor.id,
        assessment_type=assessment_type,
        status=AssessmentStatus.COMPLETED,
        responses=valid_responses,
        overall_score=effectiveness,
        risk_level=tier.value.upper(),
        domain_scores=domain_scores,
        findings=findings,
        strengths=strengths,
        assessed_by=assessed_by,
        started_date=datetime.now(),
        completed_date=datetime.now(),
        next_due_date=next_due,
    )

    # Set assessment_id on all findings
    for finding in assessment.findings:
        finding.assessment_id = assessment.id

    return assessment


def generate_assessment_summary(assessment: VendorAssessment) -> Dict:
    """
    Generate a human-readable summary of an assessment.

    Args:
        assessment: A completed VendorAssessment.

    Returns:
        Dict containing summary metrics and narrative sections.
    """
    total_findings = len(assessment.findings)
    critical_findings = sum(1 for f in assessment.findings if f.severity == FindingSeverity.CRITICAL)
    high_findings = sum(1 for f in assessment.findings if f.severity == FindingSeverity.HIGH)
    medium_findings = sum(1 for f in assessment.findings if f.severity == FindingSeverity.MEDIUM)
    low_findings = sum(1 for f in assessment.findings if f.severity == FindingSeverity.LOW)

    total_responses = len(assessment.responses)
    compliant = sum(
        1 for r in assessment.responses.values()
        if r.answer == Answer.YES
    )
    non_compliant = sum(
        1 for r in assessment.responses.values()
        if r.answer == Answer.NO
    )
    partial = sum(
        1 for r in assessment.responses.values()
        if r.answer == Answer.PARTIAL
    )
    unknown = sum(
        1 for r in assessment.responses.values()
        if r.answer == Answer.UNKNOWN
    )
    na = sum(
        1 for r in assessment.responses.values()
        if r.answer == Answer.NOT_APPLICABLE
    )

    # Weakest domains
    scored_domains = {
        d: s for d, s in assessment.domain_scores.items() if s > 0
    }
    weakest = sorted(scored_domains.items(), key=lambda x: x[1])[:3]

    return {
        "overall_score": assessment.overall_score,
        "risk_level": assessment.risk_level,
        "total_questions": total_responses,
        "response_breakdown": {
            "compliant": compliant,
            "non_compliant": non_compliant,
            "partial": partial,
            "unknown": unknown,
            "not_applicable": na,
        },
        "findings_summary": {
            "total": total_findings,
            "critical": critical_findings,
            "high": high_findings,
            "medium": medium_findings,
            "low": low_findings,
        },
        "domain_scores": assessment.domain_scores,
        "weakest_domains": [
            {"domain": d, "score": s} for d, s in weakest
        ],
        "strengths": assessment.strengths,
        "next_due_date": assessment.next_due_date.isoformat() if assessment.next_due_date else None,
    }


def _answer_label(answer: Answer) -> str:
    """Convert Answer enum to a human-readable finding title suffix."""
    labels = {
        Answer.NO: "Not Implemented",
        Answer.PARTIAL: "Partially Implemented",
        Answer.UNKNOWN: "Status Unknown",
    }
    return labels.get(answer, "Non-Compliant")
