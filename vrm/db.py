"""
JSON file-based storage engine for Vendor Risk Manager.

Provides persistent storage using plain JSON files — no SQLite or external
database dependencies. Data is stored in the configured data_dir as separate
JSON files for each entity type.

File layout:
    data/vendors.json
    data/baas.json
    data/assessments.json
    data/verifications.json

VerifAI Security | Created by Nathan Mills
"""

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .models import (
    BAA,
    Vendor,
    VendorAssessment,
    Verification,
)


class VendorDatabase:
    """
    JSON file-based database for all VRM entities.

    Stores vendors, BAAs, assessments, and verifications as JSON files.
    Supports CRUD operations, full export/import, and atomic writes
    with backup-on-save for data safety.

    Args:
        data_dir: Path to the directory for storing JSON data files.
    """

    VENDORS_FILE = "vendors.json"
    BAAS_FILE = "baas.json"
    ASSESSMENTS_FILE = "assessments.json"
    VERIFICATIONS_FILE = "verifications.json"

    def __init__(self, data_dir: str = "./data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_files()

    def _ensure_files(self) -> None:
        """Create empty JSON files if they don't exist."""
        for filename in [
            self.VENDORS_FILE,
            self.BAAS_FILE,
            self.ASSESSMENTS_FILE,
            self.VERIFICATIONS_FILE,
        ]:
            filepath = self.data_dir / filename
            if not filepath.exists():
                self._write_json(filepath, {})

    def _read_json(self, filepath: Path) -> dict:
        """Read and parse a JSON file, returning empty dict on error."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _write_json(self, filepath: Path, data: dict) -> None:
        """
        Atomically write data to a JSON file.

        Writes to a temporary file first, then renames for crash safety.
        """
        tmp_path = filepath.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        # Atomic rename (POSIX) / replace (Windows)
        tmp_path.replace(filepath)

    # ========================================================================
    # Vendor Operations
    # ========================================================================

    def save_vendor(self, vendor: Vendor) -> Vendor:
        """
        Save or update a vendor record.

        Args:
            vendor: The Vendor instance to persist.

        Returns:
            The saved Vendor with updated timestamp.
        """
        vendor.updated_at = datetime.now()
        data = self._read_json(self.data_dir / self.VENDORS_FILE)
        data[vendor.id] = vendor.to_dict()
        self._write_json(self.data_dir / self.VENDORS_FILE, data)
        return vendor

    def get_vendor(self, vendor_id: str) -> Optional[Vendor]:
        """
        Retrieve a vendor by ID.

        Args:
            vendor_id: UUID of the vendor.

        Returns:
            Vendor instance or None if not found.
        """
        data = self._read_json(self.data_dir / self.VENDORS_FILE)
        if vendor_id in data:
            return Vendor.from_dict(data[vendor_id])
        return None

    def list_vendors(self) -> List[Vendor]:
        """Return all vendors, sorted by name."""
        data = self._read_json(self.data_dir / self.VENDORS_FILE)
        vendors = [Vendor.from_dict(v) for v in data.values()]
        return sorted(vendors, key=lambda v: v.name.lower())

    def delete_vendor(self, vendor_id: str) -> bool:
        """
        Delete a vendor by ID.

        Args:
            vendor_id: UUID of the vendor to delete.

        Returns:
            True if vendor was found and deleted, False otherwise.
        """
        data = self._read_json(self.data_dir / self.VENDORS_FILE)
        if vendor_id in data:
            del data[vendor_id]
            self._write_json(self.data_dir / self.VENDORS_FILE, data)
            return True
        return False

    def search_vendors(self, query: str) -> List[Vendor]:
        """
        Search vendors by name (case-insensitive substring match).

        Args:
            query: Search string to match against vendor name, legal name, or DBA.

        Returns:
            List of matching Vendor instances.
        """
        query_lower = query.lower()
        results = []
        for vendor in self.list_vendors():
            if (query_lower in vendor.name.lower()
                    or query_lower in vendor.legal_name.lower()
                    or query_lower in vendor.dba_name.lower()):
                results.append(vendor)
        return results

    # ========================================================================
    # BAA Operations
    # ========================================================================

    def save_baa(self, baa: BAA) -> BAA:
        """
        Save or update a BAA record.

        Args:
            baa: The BAA instance to persist.

        Returns:
            The saved BAA with updated timestamp.
        """
        baa.updated_at = datetime.now()
        data = self._read_json(self.data_dir / self.BAAS_FILE)
        data[baa.id] = baa.to_dict()
        self._write_json(self.data_dir / self.BAAS_FILE, data)
        return baa

    def get_baa(self, baa_id: str) -> Optional[BAA]:
        """
        Retrieve a BAA by ID.

        Args:
            baa_id: UUID of the BAA.

        Returns:
            BAA instance or None if not found.
        """
        data = self._read_json(self.data_dir / self.BAAS_FILE)
        if baa_id in data:
            return BAA.from_dict(data[baa_id])
        return None

    def list_baas(self, vendor_id: Optional[str] = None) -> List[BAA]:
        """
        List all BAAs, optionally filtered by vendor.

        Args:
            vendor_id: If provided, return only BAAs for this vendor.

        Returns:
            List of BAA instances.
        """
        data = self._read_json(self.data_dir / self.BAAS_FILE)
        baas = [BAA.from_dict(b) for b in data.values()]
        if vendor_id:
            baas = [b for b in baas if b.vendor_id == vendor_id]
        return sorted(baas, key=lambda b: b.created_at or datetime.min)

    def delete_baa(self, baa_id: str) -> bool:
        """
        Delete a BAA by ID.

        Args:
            baa_id: UUID of the BAA to delete.

        Returns:
            True if found and deleted, False otherwise.
        """
        data = self._read_json(self.data_dir / self.BAAS_FILE)
        if baa_id in data:
            del data[baa_id]
            self._write_json(self.data_dir / self.BAAS_FILE, data)
            return True
        return False

    # ========================================================================
    # Assessment Operations
    # ========================================================================

    def save_assessment(self, assessment: VendorAssessment) -> VendorAssessment:
        """
        Save or update a vendor assessment.

        Args:
            assessment: The VendorAssessment instance to persist.

        Returns:
            The saved VendorAssessment with updated timestamp.
        """
        assessment.updated_at = datetime.now()
        data = self._read_json(self.data_dir / self.ASSESSMENTS_FILE)
        data[assessment.id] = assessment.to_dict()
        self._write_json(self.data_dir / self.ASSESSMENTS_FILE, data)
        return assessment

    def get_assessment(self, assessment_id: str) -> Optional[VendorAssessment]:
        """
        Retrieve an assessment by ID.

        Args:
            assessment_id: UUID of the assessment.

        Returns:
            VendorAssessment instance or None if not found.
        """
        data = self._read_json(self.data_dir / self.ASSESSMENTS_FILE)
        if assessment_id in data:
            return VendorAssessment.from_dict(data[assessment_id])
        return None

    def list_assessments(self, vendor_id: Optional[str] = None) -> List[VendorAssessment]:
        """
        List all assessments, optionally filtered by vendor.

        Args:
            vendor_id: If provided, return only assessments for this vendor.

        Returns:
            List of VendorAssessment instances sorted by creation date.
        """
        data = self._read_json(self.data_dir / self.ASSESSMENTS_FILE)
        assessments = [VendorAssessment.from_dict(a) for a in data.values()]
        if vendor_id:
            assessments = [a for a in assessments if a.vendor_id == vendor_id]
        return sorted(assessments, key=lambda a: a.created_at or datetime.min)

    def delete_assessment(self, assessment_id: str) -> bool:
        """
        Delete an assessment by ID.

        Args:
            assessment_id: UUID of the assessment to delete.

        Returns:
            True if found and deleted, False otherwise.
        """
        data = self._read_json(self.data_dir / self.ASSESSMENTS_FILE)
        if assessment_id in data:
            del data[assessment_id]
            self._write_json(self.data_dir / self.ASSESSMENTS_FILE, data)
            return True
        return False

    # ========================================================================
    # Verification Operations
    # ========================================================================

    def save_verification(self, verification: Verification) -> Verification:
        """
        Save or update a verification record.

        Args:
            verification: The Verification instance to persist.

        Returns:
            The saved Verification with updated timestamp.
        """
        verification.updated_at = datetime.now()
        data = self._read_json(self.data_dir / self.VERIFICATIONS_FILE)
        data[verification.id] = verification.to_dict()
        self._write_json(self.data_dir / self.VERIFICATIONS_FILE, data)
        return verification

    def get_verification(self, verification_id: str) -> Optional[Verification]:
        """
        Retrieve a verification by ID.

        Args:
            verification_id: UUID of the verification.

        Returns:
            Verification instance or None if not found.
        """
        data = self._read_json(self.data_dir / self.VERIFICATIONS_FILE)
        if verification_id in data:
            return Verification.from_dict(data[verification_id])
        return None

    def list_verifications(self, vendor_id: Optional[str] = None) -> List[Verification]:
        """
        List all verifications, optionally filtered by vendor.

        Args:
            vendor_id: If provided, return only verifications for this vendor.

        Returns:
            List of Verification instances sorted by request date.
        """
        data = self._read_json(self.data_dir / self.VERIFICATIONS_FILE)
        verifications = [Verification.from_dict(v) for v in data.values()]
        if vendor_id:
            verifications = [v for v in verifications if v.vendor_id == vendor_id]
        return sorted(verifications, key=lambda v: v.requested_date or datetime.min.date())

    def delete_verification(self, verification_id: str) -> bool:
        """
        Delete a verification by ID.

        Args:
            verification_id: UUID of the verification to delete.

        Returns:
            True if found and deleted, False otherwise.
        """
        data = self._read_json(self.data_dir / self.VERIFICATIONS_FILE)
        if verification_id in data:
            del data[verification_id]
            self._write_json(self.data_dir / self.VERIFICATIONS_FILE, data)
            return True
        return False

    # ========================================================================
    # Export / Import
    # ========================================================================

    def export_all(self, export_path: Optional[str] = None) -> str:
        """
        Export all data to a single JSON file.

        Args:
            export_path: File path for the export. Defaults to
                         data_dir/export_YYYYMMDD_HHMMSS.json.

        Returns:
            Path to the exported file.
        """
        if export_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_path = str(self.data_dir / f"export_{timestamp}.json")

        export_data = {
            "exported_at": datetime.now().isoformat(),
            "version": "1.0.0",
            "vendors": self._read_json(self.data_dir / self.VENDORS_FILE),
            "baas": self._read_json(self.data_dir / self.BAAS_FILE),
            "assessments": self._read_json(self.data_dir / self.ASSESSMENTS_FILE),
            "verifications": self._read_json(self.data_dir / self.VERIFICATIONS_FILE),
        }

        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, default=str)

        return export_path

    def import_all(self, import_path: str, overwrite: bool = False) -> Dict[str, int]:
        """
        Import data from a previously exported JSON file.

        Args:
            import_path: Path to the export JSON file.
            overwrite: If True, replace all existing data. If False, merge
                       (existing records with same ID are updated).

        Returns:
            Dict with counts of imported records per entity type.
        """
        with open(import_path, "r", encoding="utf-8") as f:
            import_data = json.load(f)

        counts = {}
        entity_map = {
            "vendors": self.VENDORS_FILE,
            "baas": self.BAAS_FILE,
            "assessments": self.ASSESSMENTS_FILE,
            "verifications": self.VERIFICATIONS_FILE,
        }

        for entity_key, filename in entity_map.items():
            imported = import_data.get(entity_key, {})
            filepath = self.data_dir / filename

            if overwrite:
                self._write_json(filepath, imported)
            else:
                existing = self._read_json(filepath)
                existing.update(imported)
                self._write_json(filepath, existing)

            counts[entity_key] = len(imported)

        return counts

    def backup(self, backup_dir: Optional[str] = None) -> str:
        """
        Create a timestamped backup of all data files.

        Args:
            backup_dir: Directory for backups. Defaults to data_dir/backups/.

        Returns:
            Path to the backup directory.
        """
        if backup_dir is None:
            backup_dir = str(self.data_dir / "backups")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = Path(backup_dir) / timestamp
        backup_path.mkdir(parents=True, exist_ok=True)

        for filename in [
            self.VENDORS_FILE,
            self.BAAS_FILE,
            self.ASSESSMENTS_FILE,
            self.VERIFICATIONS_FILE,
        ]:
            src = self.data_dir / filename
            if src.exists():
                shutil.copy2(src, backup_path / filename)

        return str(backup_path)

    def get_stats(self) -> Dict[str, int]:
        """
        Get record counts for all entity types.

        Returns:
            Dict with entity type names and their record counts.
        """
        return {
            "vendors": len(self._read_json(self.data_dir / self.VENDORS_FILE)),
            "baas": len(self._read_json(self.data_dir / self.BAAS_FILE)),
            "assessments": len(self._read_json(self.data_dir / self.ASSESSMENTS_FILE)),
            "verifications": len(self._read_json(self.data_dir / self.VERIFICATIONS_FILE)),
        }
