"""
Data models for Vendor Risk Manager.

All models use Python dataclasses with full type hints, auto-generated UUIDs,
timestamps, and JSON serialization support (to_dict / from_dict).

VerifAI Security | Created by Nathan Mills
"""

from dataclasses import dataclass, field
from datetime import datetime, date
from enum import Enum
from typing import Dict, List, Optional
import uuid


# ============================================================================
# Enumerations
# ============================================================================

class VendorType(Enum):
    """Classification of healthcare vendor types."""
    EHR_PROVIDER = "ehr_provider"
    CLOUD_SERVICE = "cloud_service"
    BILLING_SERVICE = "billing_service"
    MEDICAL_DEVICE_MFG = "medical_device_mfg"
    IT_MANAGED_SERVICE = "it_managed_service"
    CLEARINGHOUSE = "clearinghouse"
    TELEHEALTH = "telehealth"
    LAB_SYSTEM = "lab_system"
    PHARMACY_SYSTEM = "pharmacy_system"
    CONSULTING = "consulting"
    IMAGING = "imaging"
    TRANSCRIPTION = "transcription"
    DESTRUCTION_SERVICE = "destruction_service"
    INSURANCE = "insurance"
    OTHER = "other"


class VendorTier(Enum):
    """Risk tier classification based on data access and criticality."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VendorStatus(Enum):
    """Vendor lifecycle status."""
    PROSPECT = "prospect"
    ONBOARDING = "onboarding"
    ACTIVE = "active"
    UNDER_REVIEW = "under_review"
    REMEDIATION = "remediation"
    SUSPENDED = "suspended"
    OFFBOARDING = "offboarding"
    TERMINATED = "terminated"


class BAAStatus(Enum):
    """Business Associate Agreement lifecycle status."""
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    PENDING_SIGNATURE = "pending_signature"
    ACTIVE = "active"
    EXPIRED = "expired"
    TERMINATED = "terminated"
    RENEWAL_PENDING = "renewal_pending"


class DataVolume(Enum):
    """Volume of PHI records handled by vendor."""
    HIGH = "high"          # >10k records
    MEDIUM = "medium"      # 1k-10k records
    LOW = "low"            # <1k records
    NONE = "none"          # No PHI records


class AssessmentType(Enum):
    """Type of vendor security assessment."""
    INITIAL = "initial"
    ANNUAL = "annual"
    TRIGGERED = "triggered"
    REASSESSMENT = "reassessment"
    OFFBOARDING = "offboarding"


class AssessmentStatus(Enum):
    """Current status of an assessment."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    EXPIRED = "expired"


class Answer(Enum):
    """Possible responses to an assessment question."""
    YES = "yes"
    NO = "no"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class FindingSeverity(Enum):
    """Severity level of a security finding."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RemediationTimeline(Enum):
    """Expected timeline for finding remediation."""
    IMMEDIATE = "immediate"
    DAYS_30 = "30_days"
    DAYS_60 = "60_days"
    DAYS_90 = "90_days"
    DAYS_180 = "180_days"


class FindingStatus(Enum):
    """Current status of a finding."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
    DEFERRED = "deferred"


class VerificationType(Enum):
    """Type of vendor verification."""
    ANNUAL_ATTESTATION = "annual_attestation"
    TRIGGERED = "triggered"
    INCIDENT_RESPONSE = "incident_response"


class VerificationStatus(Enum):
    """Status of a verification request."""
    PENDING = "pending"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    VERIFIED = "verified"
    FAILED = "failed"
    OVERDUE = "overdue"


# ============================================================================
# PHI Types — Standard categories of Protected Health Information
# ============================================================================

PHI_TYPES = [
    "demographics",
    "diagnoses",
    "medications",
    "lab_results",
    "imaging",
    "billing",
    "insurance",
    "genetic",
    "mental_health",
    "substance_abuse",
    "hiv_aids",
]

# Sensitive PHI types that carry additional risk weighting
SENSITIVE_PHI_TYPES = {"genetic", "mental_health", "substance_abuse", "hiv_aids"}

# Integration types supported
INTEGRATION_TYPES = [
    "HL7", "FHIR", "DICOM", "Direct", "VPN", "API", "SFTP", "WEB_PORTAL", "OTHER"
]

# Clinical integration types that carry higher risk
CLINICAL_INTEGRATION_TYPES = {"HL7", "FHIR", "DICOM"}


# ============================================================================
# Serialization Helpers
# ============================================================================

def _serialize(obj):
    """Convert a value to JSON-serializable form."""
    if obj is None:
        return None
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize(v) for v in obj]
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return obj


def _deserialize_datetime(val: Optional[str]) -> Optional[datetime]:
    """Parse ISO-format datetime string, returning None for missing values."""
    if val is None:
        return None
    try:
        return datetime.fromisoformat(val)
    except (ValueError, TypeError):
        return None


def _deserialize_date(val: Optional[str]) -> Optional[date]:
    """Parse ISO-format date string, returning None for missing values."""
    if val is None:
        return None
    try:
        if "T" in str(val):
            return datetime.fromisoformat(val).date()
        return date.fromisoformat(val)
    except (ValueError, TypeError):
        return None


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class Vendor:
    """
    A third-party vendor that handles or has access to PHI.

    Tracks vendor classification, risk tier, PHI access details,
    integration methods, and lifecycle status.
    """
    name: str
    vendor_type: VendorType = VendorType.OTHER
    tier: VendorTier = VendorTier.MEDIUM
    status: VendorStatus = VendorStatus.PROSPECT
    id: str = ""
    legal_name: str = ""
    dba_name: str = ""
    phi_access: bool = False
    phi_types: List[str] = field(default_factory=list)
    data_volume: DataVolume = DataVolume.NONE
    integration_type: List[str] = field(default_factory=list)
    contact_name: str = ""
    contact_email: str = ""
    contact_phone: str = ""
    onboarded_date: Optional[date] = None
    last_review_date: Optional[date] = None
    next_review_date: Optional[date] = None
    notes: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()
        if isinstance(self.vendor_type, str):
            self.vendor_type = VendorType(self.vendor_type)
        if isinstance(self.tier, str):
            self.tier = VendorTier(self.tier)
        if isinstance(self.status, str):
            self.status = VendorStatus(self.status)
        if isinstance(self.data_volume, str):
            self.data_volume = DataVolume(self.data_volume)

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "legal_name": self.legal_name,
            "dba_name": self.dba_name,
            "vendor_type": _serialize(self.vendor_type),
            "tier": _serialize(self.tier),
            "status": _serialize(self.status),
            "phi_access": self.phi_access,
            "phi_types": self.phi_types,
            "data_volume": _serialize(self.data_volume),
            "integration_type": self.integration_type,
            "contact_name": self.contact_name,
            "contact_email": self.contact_email,
            "contact_phone": self.contact_phone,
            "onboarded_date": _serialize(self.onboarded_date),
            "last_review_date": _serialize(self.last_review_date),
            "next_review_date": _serialize(self.next_review_date),
            "notes": self.notes,
            "created_at": _serialize(self.created_at),
            "updated_at": _serialize(self.updated_at),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Vendor":
        """Deserialize from a dictionary."""
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            legal_name=data.get("legal_name", ""),
            dba_name=data.get("dba_name", ""),
            vendor_type=VendorType(data["vendor_type"]) if data.get("vendor_type") else VendorType.OTHER,
            tier=VendorTier(data["tier"]) if data.get("tier") else VendorTier.MEDIUM,
            status=VendorStatus(data["status"]) if data.get("status") else VendorStatus.PROSPECT,
            phi_access=data.get("phi_access", False),
            phi_types=data.get("phi_types", []),
            data_volume=DataVolume(data["data_volume"]) if data.get("data_volume") else DataVolume.NONE,
            integration_type=data.get("integration_type", []),
            contact_name=data.get("contact_name", ""),
            contact_email=data.get("contact_email", ""),
            contact_phone=data.get("contact_phone", ""),
            onboarded_date=_deserialize_date(data.get("onboarded_date")),
            last_review_date=_deserialize_date(data.get("last_review_date")),
            next_review_date=_deserialize_date(data.get("next_review_date")),
            notes=data.get("notes", []),
            created_at=_deserialize_datetime(data.get("created_at")),
            updated_at=_deserialize_datetime(data.get("updated_at")),
        )


@dataclass
class BAA:
    """
    Business Associate Agreement tracking.

    Monitors BAA lifecycle, compliance with new HIPAA 24-hour breach
    notification and contingency notification requirements, subcontractor
    flow-down provisions, and expiration/renewal status.
    """
    vendor_id: str
    id: str = ""
    status: BAAStatus = BAAStatus.DRAFT
    version: str = "1.0"
    effective_date: Optional[date] = None
    expiration_date: Optional[date] = None
    auto_renewal: bool = False
    renewal_term_months: int = 12
    breach_notification_hours: int = 72
    contingency_notification_hours: int = 72
    subcontractor_flow_down: bool = False
    last_updated_date: Optional[date] = None
    signed_by_vendor: str = ""
    signed_by_org: str = ""
    document_path: str = ""
    terms: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()
        if isinstance(self.status, str):
            self.status = BAAStatus(self.status)

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dictionary."""
        return {
            "id": self.id,
            "vendor_id": self.vendor_id,
            "status": _serialize(self.status),
            "version": self.version,
            "effective_date": _serialize(self.effective_date),
            "expiration_date": _serialize(self.expiration_date),
            "auto_renewal": self.auto_renewal,
            "renewal_term_months": self.renewal_term_months,
            "breach_notification_hours": self.breach_notification_hours,
            "contingency_notification_hours": self.contingency_notification_hours,
            "subcontractor_flow_down": self.subcontractor_flow_down,
            "last_updated_date": _serialize(self.last_updated_date),
            "signed_by_vendor": self.signed_by_vendor,
            "signed_by_org": self.signed_by_org,
            "document_path": self.document_path,
            "terms": self.terms,
            "notes": self.notes,
            "created_at": _serialize(self.created_at),
            "updated_at": _serialize(self.updated_at),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BAA":
        """Deserialize from a dictionary."""
        return cls(
            id=data.get("id", ""),
            vendor_id=data.get("vendor_id", ""),
            status=BAAStatus(data["status"]) if data.get("status") else BAAStatus.DRAFT,
            version=data.get("version", "1.0"),
            effective_date=_deserialize_date(data.get("effective_date")),
            expiration_date=_deserialize_date(data.get("expiration_date")),
            auto_renewal=data.get("auto_renewal", False),
            renewal_term_months=data.get("renewal_term_months", 12),
            breach_notification_hours=data.get("breach_notification_hours", 72),
            contingency_notification_hours=data.get("contingency_notification_hours", 72),
            subcontractor_flow_down=data.get("subcontractor_flow_down", False),
            last_updated_date=_deserialize_date(data.get("last_updated_date")),
            signed_by_vendor=data.get("signed_by_vendor", ""),
            signed_by_org=data.get("signed_by_org", ""),
            document_path=data.get("document_path", ""),
            terms=data.get("terms", []),
            notes=data.get("notes", []),
            created_at=_deserialize_datetime(data.get("created_at")),
            updated_at=_deserialize_datetime(data.get("updated_at")),
        )


@dataclass
class AssessmentQuestion:
    """
    A single assessment question mapped across HIPAA, NIST CSF, and HITRUST.

    Each question carries a weight (1.0-3.0) and specifies which vendor
    types it applies to. Critical questions represent mandatory requirements
    under the new HIPAA Security Rule updates.
    """
    id: str
    domain: str
    subdomain: str
    question_text: str
    hipaa_reference: str = ""
    nist_csf_reference: str = ""
    hitrust_reference: str = ""
    weight: float = 1.0
    applies_to: List[VendorType] = field(default_factory=lambda: list(VendorType))
    is_critical: bool = False

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dictionary."""
        return {
            "id": self.id,
            "domain": self.domain,
            "subdomain": self.subdomain,
            "question_text": self.question_text,
            "hipaa_reference": self.hipaa_reference,
            "nist_csf_reference": self.nist_csf_reference,
            "hitrust_reference": self.hitrust_reference,
            "weight": self.weight,
            "applies_to": [_serialize(v) for v in self.applies_to],
            "is_critical": self.is_critical,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AssessmentQuestion":
        """Deserialize from a dictionary."""
        applies_to = data.get("applies_to", [])
        if applies_to and isinstance(applies_to[0], str):
            applies_to = [VendorType(v) for v in applies_to]
        return cls(
            id=data["id"],
            domain=data.get("domain", ""),
            subdomain=data.get("subdomain", ""),
            question_text=data.get("question_text", ""),
            hipaa_reference=data.get("hipaa_reference", ""),
            nist_csf_reference=data.get("nist_csf_reference", ""),
            hitrust_reference=data.get("hitrust_reference", ""),
            weight=data.get("weight", 1.0),
            applies_to=applies_to,
            is_critical=data.get("is_critical", False),
        )


@dataclass
class AssessmentResponse:
    """
    A vendor's response to a single assessment question.

    Captures the answer, evidence status, assessor notes, and timestamp.
    """
    question_id: str
    answer: Answer = Answer.UNKNOWN
    evidence_provided: bool = False
    evidence_description: str = ""
    assessor_notes: str = ""
    assessed_date: Optional[datetime] = None

    def __post_init__(self):
        if self.assessed_date is None:
            self.assessed_date = datetime.now()
        if isinstance(self.answer, str):
            self.answer = Answer(self.answer)

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dictionary."""
        return {
            "question_id": self.question_id,
            "answer": _serialize(self.answer),
            "evidence_provided": self.evidence_provided,
            "evidence_description": self.evidence_description,
            "assessor_notes": self.assessor_notes,
            "assessed_date": _serialize(self.assessed_date),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AssessmentResponse":
        """Deserialize from a dictionary."""
        return cls(
            question_id=data.get("question_id", ""),
            answer=Answer(data["answer"]) if data.get("answer") else Answer.UNKNOWN,
            evidence_provided=data.get("evidence_provided", False),
            evidence_description=data.get("evidence_description", ""),
            assessor_notes=data.get("assessor_notes", ""),
            assessed_date=_deserialize_datetime(data.get("assessed_date")),
        )


@dataclass
class Finding:
    """
    A security finding identified during vendor assessment.

    Tracks severity, remediation timeline, ownership, and resolution status.
    Each finding maps to specific HIPAA and NIST references.
    """
    vendor_id: str
    assessment_id: str
    severity: FindingSeverity
    domain: str
    title: str
    description: str
    id: str = ""
    hipaa_reference: str = ""
    nist_reference: str = ""
    recommendation: str = ""
    remediation_timeline: RemediationTimeline = RemediationTimeline.DAYS_90
    status: FindingStatus = FindingStatus.OPEN
    owner: str = ""
    opened_date: Optional[date] = None
    due_date: Optional[date] = None
    closed_date: Optional[date] = None
    created_at: Optional[datetime] = None

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if self.opened_date is None:
            self.opened_date = date.today()
        if self.created_at is None:
            self.created_at = datetime.now()
        if isinstance(self.severity, str):
            self.severity = FindingSeverity(self.severity)
        if isinstance(self.remediation_timeline, str):
            self.remediation_timeline = RemediationTimeline(self.remediation_timeline)
        if isinstance(self.status, str):
            self.status = FindingStatus(self.status)

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dictionary."""
        return {
            "id": self.id,
            "vendor_id": self.vendor_id,
            "assessment_id": self.assessment_id,
            "severity": _serialize(self.severity),
            "domain": self.domain,
            "title": self.title,
            "description": self.description,
            "hipaa_reference": self.hipaa_reference,
            "nist_reference": self.nist_reference,
            "recommendation": self.recommendation,
            "remediation_timeline": _serialize(self.remediation_timeline),
            "status": _serialize(self.status),
            "owner": self.owner,
            "opened_date": _serialize(self.opened_date),
            "due_date": _serialize(self.due_date),
            "closed_date": _serialize(self.closed_date),
            "created_at": _serialize(self.created_at),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Deserialize from a dictionary."""
        return cls(
            id=data.get("id", ""),
            vendor_id=data.get("vendor_id", ""),
            assessment_id=data.get("assessment_id", ""),
            severity=FindingSeverity(data["severity"]) if data.get("severity") else FindingSeverity.MEDIUM,
            domain=data.get("domain", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            hipaa_reference=data.get("hipaa_reference", ""),
            nist_reference=data.get("nist_reference", ""),
            recommendation=data.get("recommendation", ""),
            remediation_timeline=RemediationTimeline(data["remediation_timeline"]) if data.get("remediation_timeline") else RemediationTimeline.DAYS_90,
            status=FindingStatus(data["status"]) if data.get("status") else FindingStatus.OPEN,
            owner=data.get("owner", ""),
            opened_date=_deserialize_date(data.get("opened_date")),
            due_date=_deserialize_date(data.get("due_date")),
            closed_date=_deserialize_date(data.get("closed_date")),
            created_at=_deserialize_datetime(data.get("created_at")),
        )


@dataclass
class VendorAssessment:
    """
    A complete vendor security assessment.

    Aggregates responses to assessment questions, calculates domain and
    overall scores, identifies findings and strengths, and tracks
    assessment lifecycle.
    """
    vendor_id: str
    assessment_type: AssessmentType = AssessmentType.INITIAL
    id: str = ""
    status: AssessmentStatus = AssessmentStatus.NOT_STARTED
    responses: Dict[str, AssessmentResponse] = field(default_factory=dict)
    overall_score: float = 0.0
    risk_level: str = ""
    domain_scores: Dict[str, float] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)
    assessed_by: str = ""
    started_date: Optional[datetime] = None
    completed_date: Optional[datetime] = None
    next_due_date: Optional[date] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()
        if isinstance(self.assessment_type, str):
            self.assessment_type = AssessmentType(self.assessment_type)
        if isinstance(self.status, str):
            self.status = AssessmentStatus(self.status)

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dictionary."""
        return {
            "id": self.id,
            "vendor_id": self.vendor_id,
            "assessment_type": _serialize(self.assessment_type),
            "status": _serialize(self.status),
            "responses": {k: v.to_dict() for k, v in self.responses.items()},
            "overall_score": self.overall_score,
            "risk_level": self.risk_level,
            "domain_scores": self.domain_scores,
            "findings": [f.to_dict() for f in self.findings],
            "strengths": self.strengths,
            "assessed_by": self.assessed_by,
            "started_date": _serialize(self.started_date),
            "completed_date": _serialize(self.completed_date),
            "next_due_date": _serialize(self.next_due_date),
            "created_at": _serialize(self.created_at),
            "updated_at": _serialize(self.updated_at),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VendorAssessment":
        """Deserialize from a dictionary."""
        responses = {}
        for k, v in data.get("responses", {}).items():
            responses[k] = AssessmentResponse.from_dict(v)
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        return cls(
            id=data.get("id", ""),
            vendor_id=data.get("vendor_id", ""),
            assessment_type=AssessmentType(data["assessment_type"]) if data.get("assessment_type") else AssessmentType.INITIAL,
            status=AssessmentStatus(data["status"]) if data.get("status") else AssessmentStatus.NOT_STARTED,
            responses=responses,
            overall_score=data.get("overall_score", 0.0),
            risk_level=data.get("risk_level", ""),
            domain_scores=data.get("domain_scores", {}),
            findings=findings,
            strengths=data.get("strengths", []),
            assessed_by=data.get("assessed_by", ""),
            started_date=_deserialize_datetime(data.get("started_date")),
            completed_date=_deserialize_datetime(data.get("completed_date")),
            next_due_date=_deserialize_date(data.get("next_due_date")),
            created_at=_deserialize_datetime(data.get("created_at")),
            updated_at=_deserialize_datetime(data.get("updated_at")),
        )


@dataclass
class Verification:
    """
    Annual Business Associate verification record.

    Implements the new HIPAA requirement for written verification that
    technical safeguards are deployed, accompanied by a qualified
    professional's written analysis and authorized representative
    certification.
    """
    vendor_id: str
    verification_type: VerificationType = VerificationType.ANNUAL_ATTESTATION
    id: str = ""
    status: VerificationStatus = VerificationStatus.PENDING
    requested_date: Optional[date] = None
    due_date: Optional[date] = None
    completed_date: Optional[date] = None
    verified_by: str = ""
    safeguards_confirmed: List[str] = field(default_factory=list)
    professional_analysis_attached: bool = False
    authorized_representative_certified: bool = False
    notes: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if self.requested_date is None:
            self.requested_date = date.today()
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()
        if isinstance(self.verification_type, str):
            self.verification_type = VerificationType(self.verification_type)
        if isinstance(self.status, str):
            self.status = VerificationStatus(self.status)

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dictionary."""
        return {
            "id": self.id,
            "vendor_id": self.vendor_id,
            "verification_type": _serialize(self.verification_type),
            "status": _serialize(self.status),
            "requested_date": _serialize(self.requested_date),
            "due_date": _serialize(self.due_date),
            "completed_date": _serialize(self.completed_date),
            "verified_by": self.verified_by,
            "safeguards_confirmed": self.safeguards_confirmed,
            "professional_analysis_attached": self.professional_analysis_attached,
            "authorized_representative_certified": self.authorized_representative_certified,
            "notes": self.notes,
            "created_at": _serialize(self.created_at),
            "updated_at": _serialize(self.updated_at),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Verification":
        """Deserialize from a dictionary."""
        return cls(
            id=data.get("id", ""),
            vendor_id=data.get("vendor_id", ""),
            verification_type=VerificationType(data["verification_type"]) if data.get("verification_type") else VerificationType.ANNUAL_ATTESTATION,
            status=VerificationStatus(data["status"]) if data.get("status") else VerificationStatus.PENDING,
            requested_date=_deserialize_date(data.get("requested_date")),
            due_date=_deserialize_date(data.get("due_date")),
            completed_date=_deserialize_date(data.get("completed_date")),
            verified_by=data.get("verified_by", ""),
            safeguards_confirmed=data.get("safeguards_confirmed", []),
            professional_analysis_attached=data.get("professional_analysis_attached", False),
            authorized_representative_certified=data.get("authorized_representative_certified", False),
            notes=data.get("notes", []),
            created_at=_deserialize_datetime(data.get("created_at")),
            updated_at=_deserialize_datetime(data.get("updated_at")),
        )


@dataclass
class RiskScore:
    """
    Computed risk score for a vendor.

    Combines inherent risk (pre-controls), control effectiveness (from
    assessment), and residual risk into a comprehensive risk profile
    with domain-level breakdowns and trend analysis.
    """
    vendor_id: str
    overall_score: float = 0.0
    risk_level: str = "MEDIUM"
    domain_scores: Dict[str, float] = field(default_factory=dict)
    inherent_risk_score: float = 0.0
    residual_risk_score: float = 0.0
    trend: str = "STABLE"
    calculated_at: Optional[datetime] = None

    def __post_init__(self):
        if self.calculated_at is None:
            self.calculated_at = datetime.now()

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dictionary."""
        return {
            "vendor_id": self.vendor_id,
            "overall_score": self.overall_score,
            "risk_level": self.risk_level,
            "domain_scores": self.domain_scores,
            "inherent_risk_score": self.inherent_risk_score,
            "residual_risk_score": self.residual_risk_score,
            "trend": self.trend,
            "calculated_at": _serialize(self.calculated_at),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RiskScore":
        """Deserialize from a dictionary."""
        return cls(
            vendor_id=data.get("vendor_id", ""),
            overall_score=data.get("overall_score", 0.0),
            risk_level=data.get("risk_level", "MEDIUM"),
            domain_scores=data.get("domain_scores", {}),
            inherent_risk_score=data.get("inherent_risk_score", 0.0),
            residual_risk_score=data.get("residual_risk_score", 0.0),
            trend=data.get("trend", "STABLE"),
            calculated_at=_deserialize_datetime(data.get("calculated_at")),
        )
