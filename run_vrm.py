#!/usr/bin/env python3
"""
VerifAI Security — Healthcare Vendor Risk Manager

Main CLI entry point. Provides command-line access to all VRM functions
including vendor management, BAA tracking, assessments, verifications,
reporting, and the demo data generator.

Usage:
    python run_vrm.py <command> [options]

Run `python run_vrm.py --help` for full command listing.

VerifAI Security | Created by Nathan Mills
"""

import argparse
import json
import os
import sys
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

# ============================================================================
# Colorama setup (graceful fallback)
# ============================================================================

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

# tqdm (graceful fallback)
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

    def tqdm(iterable, **kwargs):
        return iterable

# ============================================================================
# Project imports
# ============================================================================

from vrm.models import (
    Answer,
    AssessmentResponse,
    AssessmentStatus,
    AssessmentType,
    BAA,
    BAAStatus,
    DataVolume,
    FindingSeverity,
    FindingStatus,
    Vendor,
    VendorAssessment,
    VendorStatus,
    VendorTier,
    VendorType,
    Verification,
    VerificationStatus,
    VerificationType,
    PHI_TYPES,
    INTEGRATION_TYPES,
)
from vrm.db import VendorDatabase
from vrm.controls import get_questions_for_vendor, DOMAINS, CONTROL_INDEX
from vrm.scoring import calculate_inherent_risk, calculate_risk_score, get_risk_level_label
from vrm.risk_engine import run_assessment, generate_assessment_summary
from vrm.vendor_manager import (
    onboard_vendor,
    update_vendor_status,
    get_vendor_dashboard,
    list_vendors_by_risk,
    get_expiring_baas,
    get_overdue_assessments,
    get_vendors_needing_verification,
    offboard_vendor,
)
from vrm.baa_tracker import (
    create_baa,
    update_baa_status,
    check_baa_compliance,
    get_baa_alerts,
    renew_baa,
    get_baa_summary,
)
from vrm.verification import (
    create_verification_request,
    submit_verification,
    review_verification,
    get_verification_status_report,
    get_overdue_verifications,
)

# Reports module (built separately — handle ImportError gracefully)
try:
    from vrm.reports import (
        generate_vendor_risk_card as _gen_risk_card,
        generate_executive_report as _gen_executive,
        generate_attestation_report as _gen_attestation,
        generate_remediation_report as _gen_remediation,
    )
    HAS_REPORTS = True
except (ImportError, ModuleNotFoundError):
    HAS_REPORTS = False


# ============================================================================
# Constants & Config
# ============================================================================

BRAND = "VerifAI Security — Healthcare Vendor Risk Manager"
VERSION = "1.0.0"
DEFAULT_DATA_DIR = "./data"


# ============================================================================
# Display helpers
# ============================================================================

def _banner():
    """Print the branded banner."""
    print()
    print(f"{Fore.CYAN}{Style.BRIGHT}{'═' * 72}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}  {BRAND}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  v{VERSION}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'═' * 72}{Style.RESET_ALL}")
    print()


def _section(title: str):
    """Print a section header."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'─' * 72}{Style.RESET_ALL}")
    print(f"  {Style.BRIGHT}{title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'─' * 72}{Style.RESET_ALL}\n")


def _tier_color(tier: str) -> str:
    """Return colorama color for a risk tier."""
    t = tier.lower()
    if t == "critical":
        return Fore.RED + Style.BRIGHT
    elif t == "high":
        return Fore.YELLOW
    elif t == "medium":
        return Fore.CYAN
    elif t == "low":
        return Fore.GREEN
    return Fore.WHITE


def _score_color(score: float) -> str:
    """Return colorama color for a numeric score."""
    if score >= 80:
        return Fore.GREEN
    elif score >= 60:
        return Fore.YELLOW
    elif score >= 40:
        return Fore.YELLOW + Style.BRIGHT
    return Fore.RED + Style.BRIGHT


def _severity_color(severity: str) -> str:
    """Return colorama color for finding severity."""
    s = severity.lower()
    if s == "critical":
        return Fore.RED + Style.BRIGHT
    elif s == "high":
        return Fore.YELLOW + Style.BRIGHT
    elif s == "medium":
        return Fore.YELLOW
    return Fore.WHITE


def _status_color(status: str) -> str:
    """Return colorama color for generic status strings."""
    s = status.lower()
    if s in ("active", "verified", "compliant", "ok"):
        return Fore.GREEN
    elif s in ("pending", "pending_signature", "renewal_pending", "submitted", "warning"):
        return Fore.YELLOW
    elif s in ("expired", "failed", "critical", "non_compliant", "overdue", "terminated"):
        return Fore.RED + Style.BRIGHT
    return Fore.WHITE


def _badge(label: str, color: str) -> str:
    """Return a colored badge string."""
    return f"{color}[{label}]{Style.RESET_ALL}"


def _get_db(args) -> VendorDatabase:
    """Initialize and return the database from args."""
    data_dir = getattr(args, "data_dir", DEFAULT_DATA_DIR)
    return VendorDatabase(data_dir=data_dir)


def _find_vendor(db: VendorDatabase, vendor_id: str) -> Optional[Vendor]:
    """Look up a vendor by ID or name substring."""
    # Try exact ID first
    vendor = db.get_vendor(vendor_id)
    if vendor:
        return vendor
    # Try search by name
    results = db.search_vendors(vendor_id)
    if len(results) == 1:
        return results[0]
    elif len(results) > 1:
        print(f"{Fore.YELLOW}Multiple vendors match '{vendor_id}':{Style.RESET_ALL}")
        for v in results:
            print(f"  {v.id[:12]}...  {v.name}")
        print(f"\n{Fore.YELLOW}Please use a full vendor ID.{Style.RESET_ALL}")
        return None
    print(f"{Fore.RED}Vendor '{vendor_id}' not found.{Style.RESET_ALL}")
    return None


# ============================================================================
# Command: demo
# ============================================================================

def cmd_demo(args):
    """Generate demo organization with 8 vendors."""
    from demo.demo_org import generate_demo_org

    data_dir = getattr(args, "data_dir", DEFAULT_DATA_DIR)
    db, path = generate_demo_org(data_dir=data_dir, verbose=True)

    # Store the data dir so subsequent commands use it
    return db


# ============================================================================
# Command: vendor add
# ============================================================================

def cmd_vendor_add(args):
    """Interactive vendor onboarding."""
    _banner()
    print(f"  {Style.BRIGHT}New Vendor Onboarding{Style.RESET_ALL}\n")

    db = _get_db(args)

    # Collect vendor information
    name = input(f"  Vendor name: ").strip()
    if not name:
        print(f"{Fore.RED}  Vendor name is required.{Style.RESET_ALL}")
        return

    legal_name = input(f"  Legal name (or Enter to use vendor name): ").strip() or name

    print(f"\n  {Style.BRIGHT}Vendor types:{Style.RESET_ALL}")
    type_list = list(VendorType)
    for i, vt in enumerate(type_list, 1):
        print(f"    {i:2d}. {vt.value.replace('_', ' ').title()}")
    type_idx = input(f"\n  Select vendor type [1-{len(type_list)}]: ").strip()
    try:
        vendor_type = type_list[int(type_idx) - 1]
    except (ValueError, IndexError):
        vendor_type = VendorType.OTHER

    phi_access = input(f"  Does vendor access PHI? (y/n) [y]: ").strip().lower()
    phi_access = phi_access != "n"

    phi_types = []
    if phi_access:
        print(f"\n  {Style.BRIGHT}PHI types (comma-separated):{Style.RESET_ALL}")
        for i, pt in enumerate(PHI_TYPES, 1):
            print(f"    {i:2d}. {pt}")
        phi_input = input(f"\n  Select PHI types (e.g., 1,2,3 or Enter for all): ").strip()
        if phi_input:
            for idx in phi_input.split(","):
                try:
                    phi_types.append(PHI_TYPES[int(idx.strip()) - 1])
                except (ValueError, IndexError):
                    pass
        else:
            phi_types = list(PHI_TYPES)

    print(f"\n  {Style.BRIGHT}Data volume:{Style.RESET_ALL}")
    for i, dv in enumerate(DataVolume, 1):
        print(f"    {i}. {dv.value.upper()}")
    dv_idx = input(f"  Select data volume [1-4]: ").strip()
    try:
        data_volume = list(DataVolume)[int(dv_idx) - 1]
    except (ValueError, IndexError):
        data_volume = DataVolume.MEDIUM

    print(f"\n  {Style.BRIGHT}Integration types (comma-separated):{Style.RESET_ALL}")
    for i, it in enumerate(INTEGRATION_TYPES, 1):
        print(f"    {i:2d}. {it}")
    int_input = input(f"  Select integrations (e.g., 1,2 or Enter for none): ").strip()
    integrations = []
    if int_input:
        for idx in int_input.split(","):
            try:
                integrations.append(INTEGRATION_TYPES[int(idx.strip()) - 1])
            except (ValueError, IndexError):
                pass

    contact_name = input(f"\n  Contact name: ").strip()
    contact_email = input(f"  Contact email: ").strip()
    contact_phone = input(f"  Contact phone: ").strip()

    # Create vendor
    vendor_data = {
        "name": name,
        "legal_name": legal_name,
        "vendor_type": vendor_type.value,
        "phi_access": phi_access,
        "phi_types": phi_types,
        "data_volume": data_volume.value,
        "integration_type": integrations,
        "contact_name": contact_name,
        "contact_email": contact_email,
        "contact_phone": contact_phone,
    }

    vendor = onboard_vendor(vendor_data, db)
    inherent = calculate_inherent_risk(vendor)

    print(f"\n{Fore.GREEN}{Style.BRIGHT}  ✓ Vendor onboarded successfully{Style.RESET_ALL}")
    print(f"    ID:            {vendor.id}")
    print(f"    Name:          {vendor.name}")
    print(f"    Type:          {vendor.vendor_type.value}")
    print(f"    Status:        {vendor.status.value}")
    print(f"    Inherent Risk: {_score_color(100 - inherent)}{inherent:.1f}/100{Style.RESET_ALL}")
    print(f"    Next Review:   {vendor.next_review_date}")
    print()


# ============================================================================
# Command: vendor list
# ============================================================================

def cmd_vendor_list(args):
    """List all vendors sorted by risk."""
    _banner()
    db = _get_db(args)
    vendors = list_vendors_by_risk(db)

    if not vendors:
        print(f"  {Fore.YELLOW}No vendors in the database.{Style.RESET_ALL}")
        print(f"  Run {Style.BRIGHT}python run_vrm.py demo{Style.RESET_ALL} to generate demo data.\n")
        return

    _section(f"Vendor Portfolio — {len(vendors)} Vendors")

    # Header
    print(
        f"  {'Vendor':<30} {'Type':<18} {'Score':>6}  {'Tier':<10} "
        f"{'BAA':<12} {'PHI':>4}  {'Status':<12}"
    )
    print(f"  {'─' * 30} {'─' * 18} {'─' * 6}  {'─' * 10} {'─' * 12} {'─' * 4}  {'─' * 12}")

    for v in vendors:
        name = v["vendor_name"][:29]
        vtype = v["vendor_type"].replace("_", " ")[:17]
        score = v.get("assessment_score")
        score_str = f"{score:5.1f}" if score is not None else "  N/A"
        sc = _score_color(score) if score is not None else Fore.WHITE
        tier = v["risk_level"]
        tc = _tier_color(tier)
        baa = v["baa_status"]
        bc = _status_color(baa)
        phi = "Yes" if v["phi_access"] else "No"
        status = v["status"]

        print(
            f"  {name:<30} {vtype:<18} {sc}{score_str}{Style.RESET_ALL}  "
            f"{tc}{tier:<10}{Style.RESET_ALL} "
            f"{bc}{baa:<12}{Style.RESET_ALL} {phi:>4}  {status:<12}"
        )

    print()


# ============================================================================
# Command: vendor dashboard
# ============================================================================

def cmd_vendor_dashboard(args):
    """Show detailed vendor dashboard."""
    _banner()
    db = _get_db(args)

    vendor = _find_vendor(db, args.vendor_id)
    if not vendor:
        return

    dashboard = get_vendor_dashboard(vendor.id, db)
    v = dashboard["vendor"]

    _section(f"Vendor Dashboard — {v['name']}")

    # Basic info
    print(f"  {Style.BRIGHT}Vendor ID:{Style.RESET_ALL}     {v['id']}")
    print(f"  {Style.BRIGHT}Legal Name:{Style.RESET_ALL}    {v['legal_name'] or v['name']}")
    print(f"  {Style.BRIGHT}Type:{Style.RESET_ALL}          {v['vendor_type'].replace('_', ' ').title()}")
    print(f"  {Style.BRIGHT}Status:{Style.RESET_ALL}        {_status_color(v['status'])}{v['status'].upper()}{Style.RESET_ALL}")
    print(f"  {Style.BRIGHT}Tier:{Style.RESET_ALL}          {_tier_color(v['tier'])}{v['tier'].upper()}{Style.RESET_ALL}")
    print(f"  {Style.BRIGHT}PHI Access:{Style.RESET_ALL}    {'Yes' if v['phi_access'] else 'No'}")
    if v['phi_types']:
        print(f"  {Style.BRIGHT}PHI Types:{Style.RESET_ALL}     {', '.join(v['phi_types'])}")
    print(f"  {Style.BRIGHT}Data Volume:{Style.RESET_ALL}   {v['data_volume'].upper()}")
    print(f"  {Style.BRIGHT}Integrations:{Style.RESET_ALL}  {', '.join(v['integration_type']) or 'None'}")
    print(f"  {Style.BRIGHT}Contact:{Style.RESET_ALL}       {v['contact_name']} <{v['contact_email']}>")
    print(f"  {Style.BRIGHT}Inherent Risk:{Style.RESET_ALL} {dashboard['inherent_risk_score']:.1f}/100")

    # BAA
    _section("Business Associate Agreement")
    baa = dashboard.get("current_baa")
    if baa:
        print(f"  {Style.BRIGHT}BAA ID:{Style.RESET_ALL}        {baa['id'][:12]}...")
        print(f"  {Style.BRIGHT}Status:{Style.RESET_ALL}        {_status_color(baa['status'])}{baa['status'].upper()}{Style.RESET_ALL}")
        print(f"  {Style.BRIGHT}Effective:{Style.RESET_ALL}     {baa.get('effective_date', 'N/A')}")
        print(f"  {Style.BRIGHT}Expiration:{Style.RESET_ALL}    {baa.get('expiration_date', 'N/A')}")
        print(f"  {Style.BRIGHT}Breach Notif:{Style.RESET_ALL}  {baa['breach_notification_hours']}h "
              f"{'(' + Fore.GREEN + 'compliant' + Style.RESET_ALL + ')' if baa['breach_notification_hours'] <= 24 else '(' + Fore.RED + 'NON-COMPLIANT — 24h required' + Style.RESET_ALL + ')'}")
        print(f"  {Style.BRIGHT}Flow-down:{Style.RESET_ALL}     {'Yes' if baa['subcontractor_flow_down'] else Fore.YELLOW + 'No' + Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}{Style.BRIGHT}  NO ACTIVE BAA ON FILE{Style.RESET_ALL}")

    # Assessment
    _section("Latest Assessment")
    assess = dashboard.get("latest_assessment")
    if assess:
        score = assess["overall_score"]
        print(f"  {Style.BRIGHT}Score:{Style.RESET_ALL}         {_score_color(score)}{score:.1f}/100{Style.RESET_ALL}")
        print(f"  {Style.BRIGHT}Risk Level:{Style.RESET_ALL}    {_tier_color(assess['risk_level'])}{assess['risk_level']}{Style.RESET_ALL}")
        print(f"  {Style.BRIGHT}Completed:{Style.RESET_ALL}     {assess.get('completed_date', 'N/A')}")
        print(f"  {Style.BRIGHT}Next Due:{Style.RESET_ALL}      {assess.get('next_due_date', 'N/A')}")

        print(f"\n  {Style.BRIGHT}Domain Scores:{Style.RESET_ALL}")
        for domain, dscore in assess.get("domain_scores", {}).items():
            if dscore > 0:
                bar_len = int(dscore / 100 * 30)
                bar = "█" * bar_len + "░" * (30 - bar_len)
                print(f"    {domain:<45} {_score_color(dscore)}{bar} {dscore:5.1f}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.YELLOW}  No assessment on record{Style.RESET_ALL}")

    # Findings
    findings = dashboard.get("open_findings", {})
    if findings.get("total", 0) > 0:
        _section(f"Open Findings ({findings['total']})")
        for sev, count_key, color in [
            ("CRITICAL", "critical", Fore.RED + Style.BRIGHT),
            ("HIGH", "high", Fore.YELLOW + Style.BRIGHT),
            ("MEDIUM", "medium", Fore.YELLOW),
            ("LOW", "low", Fore.WHITE),
        ]:
            count = findings.get(count_key, 0)
            if count > 0:
                print(f"    {color}{sev:<10}{Style.RESET_ALL}  {count}")
        overdue = findings.get("overdue", 0)
        if overdue:
            print(f"\n    {Fore.RED}Overdue: {overdue} finding(s) past remediation deadline{Style.RESET_ALL}")

    # Verification
    v_data = dashboard.get("verification")
    if v_data:
        _section("Verification Status")
        v_status = v_data["status"]
        print(f"  {Style.BRIGHT}Status:{Style.RESET_ALL}    {_status_color(v_status)}{v_status.upper()}{Style.RESET_ALL}")
        if v_data.get("completed_date"):
            print(f"  {Style.BRIGHT}Completed:{Style.RESET_ALL} {v_data['completed_date']}")
        if v_data.get("due_date"):
            print(f"  {Style.BRIGHT}Due Date:{Style.RESET_ALL}  {v_data['due_date']}")

    # Action items
    actions = dashboard.get("action_items", [])
    if actions:
        _section("Action Items")
        for action in actions:
            if action.startswith("CRITICAL"):
                color = Fore.RED + Style.BRIGHT
            elif action.startswith("WARNING"):
                color = Fore.YELLOW
            else:
                color = Fore.WHITE
            print(f"    {color}• {action}{Style.RESET_ALL}")

    # Strengths
    strengths = dashboard.get("strengths", [])
    if strengths:
        _section("Strengths")
        for s in strengths:
            print(f"    {Fore.GREEN}✓ {s}{Style.RESET_ALL}")

    print()


# ============================================================================
# Command: vendor offboard
# ============================================================================

def cmd_vendor_offboard(args):
    """Offboard a vendor."""
    _banner()
    db = _get_db(args)

    vendor = _find_vendor(db, args.vendor_id)
    if not vendor:
        return

    print(f"  {Fore.YELLOW}Offboarding vendor: {Style.BRIGHT}{vendor.name}{Style.RESET_ALL}")
    reason = input(f"  Reason for offboarding: ").strip() or "Contract termination"

    result = offboard_vendor(vendor.id, db, reason=reason)

    print(f"\n{Fore.GREEN}{Style.BRIGHT}  ✓ Offboarding initiated{Style.RESET_ALL}")
    print(f"\n  {Style.BRIGHT}Offboarding Checklist ({result['total_items']} items):{Style.RESET_ALL}\n")

    for item in result["checklist"]:
        print(f"    [ ] {item['item']}")
        print(f"        {Fore.WHITE}{item['description']}{Style.RESET_ALL}")

    print()
    for note in result["notes"]:
        print(f"    {Fore.YELLOW}• {note}{Style.RESET_ALL}")
    print()


# ============================================================================
# Command: baa create
# ============================================================================

def cmd_baa_create(args):
    """Create a new BAA interactively."""
    _banner()
    db = _get_db(args)

    vendor = _find_vendor(db, args.vendor_id)
    if not vendor:
        return

    print(f"  {Style.BRIGHT}Create BAA for: {vendor.name}{Style.RESET_ALL}\n")

    eff = input("  Effective date (YYYY-MM-DD, Enter for today): ").strip()
    effective_date = date.fromisoformat(eff) if eff else date.today()

    exp = input("  Expiration date (YYYY-MM-DD, Enter for +1 year): ").strip()
    expiration_date = date.fromisoformat(exp) if exp else effective_date + timedelta(days=365)

    breach_hours = input("  Breach notification hours [24]: ").strip()
    breach_hours = int(breach_hours) if breach_hours else 24

    contingency_hours = input("  Contingency notification hours [24]: ").strip()
    contingency_hours = int(contingency_hours) if contingency_hours else 24

    flow_down = input("  Subcontractor flow-down? (y/n) [y]: ").strip().lower()
    flow_down = flow_down != "n"

    auto_renewal = input("  Auto-renewal? (y/n) [n]: ").strip().lower()
    auto_renewal = auto_renewal == "y"

    signed_vendor = input("  Signed by vendor (name): ").strip()
    signed_org = input("  Signed by organization (name): ").strip()

    terms = {
        "effective_date": effective_date,
        "expiration_date": expiration_date,
        "breach_notification_hours": breach_hours,
        "contingency_notification_hours": contingency_hours,
        "subcontractor_flow_down": flow_down,
        "auto_renewal": auto_renewal,
        "signed_by_vendor": signed_vendor,
        "signed_by_org": signed_org,
    }

    baa = create_baa(vendor.id, terms, db)

    print(f"\n{Fore.GREEN}{Style.BRIGHT}  ✓ BAA created{Style.RESET_ALL}")
    print(f"    BAA ID:     {baa.id}")
    print(f"    Status:     {baa.status.value}")
    print(f"    Effective:  {baa.effective_date}")
    print(f"    Expiration: {baa.expiration_date}")
    print()


# ============================================================================
# Command: baa list
# ============================================================================

def cmd_baa_list(args):
    """List all BAAs with status."""
    _banner()
    db = _get_db(args)
    baas = db.list_baas()

    if not baas:
        print(f"  {Fore.YELLOW}No BAAs in the database.{Style.RESET_ALL}\n")
        return

    _section(f"Business Associate Agreements — {len(baas)} Total")

    print(
        f"  {'Vendor':<30} {'Status':<18} {'Effective':<12} {'Expiration':<12} "
        f"{'Breach':>7}  {'Flow-Down':>10}"
    )
    print(f"  {'─' * 30} {'─' * 18} {'─' * 12} {'─' * 12} {'─' * 7}  {'─' * 10}")

    for baa in baas:
        vendor = db.get_vendor(baa.vendor_id)
        vname = (vendor.name if vendor else "Unknown")[:29]
        status = baa.status.value.upper().replace("_", " ")
        sc = _status_color(baa.status.value)
        eff = str(baa.effective_date or "N/A")[:11]
        exp = str(baa.expiration_date or "N/A")[:11]
        breach = f"{baa.breach_notification_hours}h"
        breach_color = Fore.GREEN if baa.breach_notification_hours <= 24 else Fore.RED
        flow = "Yes" if baa.subcontractor_flow_down else "No"
        flow_color = Fore.GREEN if baa.subcontractor_flow_down else Fore.YELLOW

        print(
            f"  {vname:<30} {sc}{status:<18}{Style.RESET_ALL} {eff:<12} {exp:<12} "
            f"{breach_color}{breach:>7}{Style.RESET_ALL}  {flow_color}{flow:>10}{Style.RESET_ALL}"
        )

    print()


# ============================================================================
# Command: baa alerts
# ============================================================================

def cmd_baa_alerts(args):
    """Show all BAA alerts."""
    _banner()
    db = _get_db(args)
    alerts = get_baa_alerts(db)

    if not alerts:
        print(f"  {Fore.GREEN}No BAA alerts — all agreements are in order.{Style.RESET_ALL}\n")
        return

    _section(f"BAA Alerts — {len(alerts)} Issue(s)")

    for alert in alerts:
        sev = alert["severity"]
        color = _severity_color(sev)
        print(f"  {color}{_badge(sev, color)}{Style.RESET_ALL} {alert['message']}")
        print(f"         {Fore.WHITE}Action: {alert['action']}{Style.RESET_ALL}")
        if alert.get("baa_id"):
            print(f"         BAA ID: {alert['baa_id'][:12]}...")
        print()


# ============================================================================
# Command: baa check
# ============================================================================

def cmd_baa_check(args):
    """Check specific BAA compliance."""
    _banner()
    db = _get_db(args)

    baa = db.get_baa(args.baa_id)
    if not baa:
        # Try finding by vendor name
        vendors = db.search_vendors(args.baa_id)
        if vendors:
            vendor_baas = db.list_baas(vendor_id=vendors[0].id)
            if vendor_baas:
                baa = vendor_baas[-1]

    if not baa:
        print(f"{Fore.RED}  BAA '{args.baa_id}' not found.{Style.RESET_ALL}\n")
        return

    result = check_baa_compliance(baa.id, db)

    _section(f"BAA Compliance Check — {result['vendor_name']}")

    overall = result["overall_compliance"]
    oc = _status_color(overall.lower().replace("_", " "))
    print(f"  {Style.BRIGHT}Overall:{Style.RESET_ALL}  {oc}{overall}{Style.RESET_ALL}")
    print()

    for check_name, check in result["checks"].items():
        sev = check.get("severity", "OK")
        color = _severity_color(sev) if sev != "OK" else Fore.GREEN
        icon = "✓" if check.get("compliant") else "✗"
        print(f"  {color}{icon}{Style.RESET_ALL}  {check_name.replace('_', ' ').title()}")
        print(f"     {Fore.WHITE}{check['detail']}{Style.RESET_ALL}")
        print()

    if result["recommendations"]:
        print(f"  {Style.BRIGHT}Recommendations:{Style.RESET_ALL}")
        for rec in result["recommendations"]:
            print(f"    {Fore.YELLOW}• {rec}{Style.RESET_ALL}")
        print()


# ============================================================================
# Command: assess (interactive)
# ============================================================================

def cmd_assess(args):
    """Run interactive assessment for a vendor."""
    _banner()
    db = _get_db(args)

    vendor = _find_vendor(db, args.vendor_id)
    if not vendor:
        return

    questions = get_questions_for_vendor(vendor.vendor_type, vendor.phi_access)
    print(f"  {Style.BRIGHT}Assessment for: {vendor.name}{Style.RESET_ALL}")
    print(f"  {len(questions)} applicable questions\n")

    answer_map = {
        "y": Answer.YES, "yes": Answer.YES,
        "n": Answer.NO, "no": Answer.NO,
        "p": Answer.PARTIAL, "partial": Answer.PARTIAL,
        "na": Answer.NOT_APPLICABLE, "not_applicable": Answer.NOT_APPLICABLE,
        "u": Answer.UNKNOWN, "unknown": Answer.UNKNOWN,
        "s": Answer.UNKNOWN,  # skip → unknown
    }

    responses: Dict[str, AssessmentResponse] = {}
    current_domain = ""

    iterable = tqdm(questions, desc="  Assessment progress", unit="q") if HAS_TQDM else questions

    for q in iterable:
        if q.domain != current_domain:
            current_domain = q.domain
            if HAS_TQDM:
                tqdm.write(f"\n  {Fore.CYAN}{Style.BRIGHT}━━ {current_domain} ━━{Style.RESET_ALL}")
            else:
                print(f"\n  {Fore.CYAN}{Style.BRIGHT}━━ {current_domain} ━━{Style.RESET_ALL}")

        q_text = q.question_text
        refs = []
        if q.hipaa_reference:
            refs.append(f"HIPAA {q.hipaa_reference}")
        if q.nist_csf_reference:
            refs.append(f"NIST {q.nist_csf_reference}")
        if q.hitrust_reference:
            refs.append(f"HITRUST {q.hitrust_reference}")
        ref_str = f" [{', '.join(refs)}]" if refs else ""

        critical_mark = f" {Fore.RED}★ CRITICAL{Style.RESET_ALL}" if q.is_critical else ""
        prompt = (
            f"\n  {Style.BRIGHT}{q.id}{Style.RESET_ALL} {q_text}"
            f"\n  {Fore.WHITE}{ref_str}{critical_mark}{Style.RESET_ALL}"
            f"\n  Answer (y/n/p/na/u/s): "
        )

        if HAS_TQDM:
            tqdm.write(prompt, end="")
        else:
            print(prompt, end="")

        raw = input().strip().lower()
        answer = answer_map.get(raw, Answer.UNKNOWN)

        responses[q.id] = AssessmentResponse(
            question_id=q.id,
            answer=answer,
        )

    # Run assessment
    print(f"\n  {Fore.CYAN}Scoring assessment...{Style.RESET_ALL}")

    assessment = run_assessment(
        vendor=vendor,
        assessment_type=AssessmentType.ANNUAL,
        responses=responses,
        assessed_by="CLI Interactive Assessment",
        db=db,
    )

    db.save_assessment(assessment)

    # Update vendor tier
    vendor.tier = VendorTier(assessment.risk_level.lower())
    vendor.last_review_date = date.today()
    db.save_vendor(vendor)

    # Show results
    _section("Assessment Results")
    score = assessment.overall_score
    print(f"  {Style.BRIGHT}Overall Score:{Style.RESET_ALL}  {_score_color(score)}{score:.1f}/100{Style.RESET_ALL}")
    print(f"  {Style.BRIGHT}Risk Level:{Style.RESET_ALL}     {_tier_color(assessment.risk_level)}{assessment.risk_level}{Style.RESET_ALL}")
    print(f"  {Style.BRIGHT}Findings:{Style.RESET_ALL}       {len(assessment.findings)}")

    summary = generate_assessment_summary(assessment)
    if summary.get("findings_summary", {}).get("critical", 0) > 0:
        print(f"  {Fore.RED}{Style.BRIGHT}  ⚠  {summary['findings_summary']['critical']} CRITICAL findings{Style.RESET_ALL}")

    print(f"\n  Assessment ID: {assessment.id}")
    print()


# ============================================================================
# Command: assess quick
# ============================================================================

def cmd_assess_quick(args):
    """Quick assessment with random demo responses."""
    _banner()
    db = _get_db(args)

    vendor = _find_vendor(db, args.vendor_id)
    if not vendor:
        return

    import random
    rng = random.Random(42)

    questions = get_questions_for_vendor(vendor.vendor_type, vendor.phi_access)
    print(f"  {Style.BRIGHT}Quick Assessment for: {vendor.name}{Style.RESET_ALL}")
    print(f"  {len(questions)} applicable questions — generating random responses...\n")

    responses: Dict[str, AssessmentResponse] = {}
    for q in questions:
        # Random but weighted toward YES for a realistic spread
        roll = rng.random()
        if roll < 0.55:
            answer = Answer.YES
        elif roll < 0.75:
            answer = Answer.PARTIAL
        elif roll < 0.90:
            answer = Answer.NO
        else:
            answer = Answer.UNKNOWN

        responses[q.id] = AssessmentResponse(
            question_id=q.id,
            answer=answer,
        )

    assessment = run_assessment(
        vendor=vendor,
        assessment_type=AssessmentType.ANNUAL,
        responses=responses,
        assessed_by="Quick Assessment (Demo)",
        db=db,
    )

    db.save_assessment(assessment)

    vendor.tier = VendorTier(assessment.risk_level.lower())
    vendor.last_review_date = date.today()
    db.save_vendor(vendor)

    score = assessment.overall_score
    print(f"  {Style.BRIGHT}Score:{Style.RESET_ALL}      {_score_color(score)}{score:.1f}/100{Style.RESET_ALL}")
    print(f"  {Style.BRIGHT}Risk Level:{Style.RESET_ALL} {_tier_color(assessment.risk_level)}{assessment.risk_level}{Style.RESET_ALL}")
    print(f"  {Style.BRIGHT}Findings:{Style.RESET_ALL}   {len(assessment.findings)}")
    print(f"  Assessment ID: {assessment.id}\n")


# ============================================================================
# Command: verify request
# ============================================================================

def cmd_verify_request(args):
    """Send verification request to a vendor."""
    _banner()
    db = _get_db(args)

    vendor = _find_vendor(db, args.vendor_id)
    if not vendor:
        return

    try:
        verification = create_verification_request(vendor.id, db)
        print(f"{Fore.GREEN}{Style.BRIGHT}  ✓ Verification request created{Style.RESET_ALL}")
        print(f"    ID:       {verification.id}")
        print(f"    Vendor:   {vendor.name}")
        print(f"    Due Date: {verification.due_date}")
        print()
    except ValueError as e:
        print(f"{Fore.RED}  Error: {e}{Style.RESET_ALL}\n")


# ============================================================================
# Command: verify submit
# ============================================================================

def cmd_verify_submit(args):
    """Submit verification for a vendor."""
    _banner()
    db = _get_db(args)

    verification = db.get_verification(args.verification_id)
    if not verification:
        print(f"{Fore.RED}  Verification '{args.verification_id}' not found.{Style.RESET_ALL}\n")
        return

    vendor = db.get_vendor(verification.vendor_id)
    print(f"  {Style.BRIGHT}Submit Verification for: {vendor.name if vendor else 'Unknown'}{Style.RESET_ALL}\n")

    print(f"  {Style.BRIGHT}Safeguard categories to confirm:{Style.RESET_ALL}")
    categories = [
        "access_controls", "encryption", "audit_logging",
        "incident_response", "backup_recovery",
    ]
    confirmed = []
    for cat in categories:
        resp = input(f"    {cat}? (y/n) [y]: ").strip().lower()
        if resp != "n":
            confirmed.append(cat)

    analysis = input(f"\n  Professional analysis attached? (y/n) [y]: ").strip().lower()
    analysis = analysis != "n"

    cert = input(f"  Authorized representative certified? (y/n) [y]: ").strip().lower()
    cert = cert != "n"

    verified_by = input(f"  Submitted by (name): ").strip() or "CLI User"

    try:
        result = submit_verification(
            args.verification_id, confirmed, analysis, cert, db,
            verified_by=verified_by,
        )
        print(f"\n{Fore.GREEN}{Style.BRIGHT}  ✓ Verification submitted{Style.RESET_ALL}")
        print(f"    Status: {result.status.value}")
        print()

        # Auto-review
        review = input(f"  Run auto-review now? (y/n) [y]: ").strip().lower()
        if review != "n":
            review_result = review_verification(result.id, db, reviewer=verified_by)
            status = review_result["result"]
            sc = Fore.GREEN if status == "VERIFIED" else Fore.RED
            print(f"\n  {Style.BRIGHT}Review Result:{Style.RESET_ALL} {sc}{status}{Style.RESET_ALL}")
            if review_result["failures"]:
                for f in review_result["failures"]:
                    print(f"    {Fore.RED}• {f}{Style.RESET_ALL}")
            print()
    except ValueError as e:
        print(f"{Fore.RED}  Error: {e}{Style.RESET_ALL}\n")


# ============================================================================
# Command: verify status
# ============================================================================

def cmd_verify_status(args):
    """Org-wide verification status report."""
    _banner()
    db = _get_db(args)
    report = get_verification_status_report(db)

    _section(f"Verification Status Report — {report['report_date']}")

    print(f"  {Style.BRIGHT}Total vendors:{Style.RESET_ALL}           {report['total_vendors']}")
    print(f"  {Style.BRIGHT}Verification required:{Style.RESET_ALL}   {report['verification_required']}")
    print(f"  {Style.BRIGHT}Compliance rate:{Style.RESET_ALL}         {_score_color(report['compliance_percentage'])}{report['compliance_percentage']:.1f}%{Style.RESET_ALL}")

    breakdown = report["status_breakdown"]
    print(f"\n  {Style.BRIGHT}Status Breakdown:{Style.RESET_ALL}")
    for status, count in breakdown.items():
        if count > 0:
            sc = _status_color(status)
            print(f"    {sc}{status.upper():<20}{Style.RESET_ALL} {count}")

    needing_action = report.get("vendors_needing_action", [])
    if needing_action:
        print(f"\n  {Style.BRIGHT}Vendors Needing Action:{Style.RESET_ALL}")
        for v in needing_action:
            sc = _status_color(v["status"])
            print(f"    {sc}{v['status']:<16}{Style.RESET_ALL} {v['vendor_name']}")
    print()


# ============================================================================
# Command: report (all report subcommands)
# ============================================================================

def _get_vendor_report_data(db: VendorDatabase, vendor: Vendor) -> dict:
    """Gather all data for a vendor needed by report generators."""
    from vrm.scoring import calculate_risk_score
    assessments = db.list_assessments(vendor_id=vendor.id)
    latest_assessment = None
    for a in reversed(assessments):
        if a.status == AssessmentStatus.COMPLETED:
            latest_assessment = a
            break

    baas = db.list_baas(vendor_id=vendor.id)
    active_baa = None
    for b in reversed(baas):
        if b.status in (BAAStatus.ACTIVE, BAAStatus.RENEWAL_PENDING, BAAStatus.PENDING_SIGNATURE):
            active_baa = b
            break

    verifications = db.list_verifications(vendor_id=vendor.id)
    latest_verification = verifications[-1] if verifications else None

    risk_score = None
    if latest_assessment:
        risk_score = calculate_risk_score(vendor, latest_assessment)

    return {
        "vendor": vendor,
        "assessment": latest_assessment,
        "baa": active_baa,
        "verification": latest_verification,
        "risk_score": risk_score,
    }


def cmd_report_risk_card(args):
    """Generate vendor risk card PDF."""
    if not HAS_REPORTS:
        print(f"{Fore.YELLOW}  Reports module not yet available. It is being built separately.{Style.RESET_ALL}\n")
        return
    _banner()
    db = _get_db(args)
    vendor = _find_vendor(db, args.vendor_id)
    if not vendor:
        return

    data = _get_vendor_report_data(db, vendor)
    output = f"./reports/risk_card_{vendor.name.lower().replace(' ', '_')}.pdf"
    os.makedirs(os.path.dirname(output), exist_ok=True)

    path = _gen_risk_card(
        vendor=data["vendor"],
        assessment=data["assessment"],
        baa=data["baa"],
        verification=data["verification"],
        risk_score=data["risk_score"],
        output_path=output,
    )
    print(f"{Fore.GREEN}  \u2713 Risk card generated: {path}{Style.RESET_ALL}\n")


def cmd_report_executive(args):
    """Generate executive portfolio PDF."""
    if not HAS_REPORTS:
        print(f"{Fore.YELLOW}  Reports module not yet available. It is being built separately.{Style.RESET_ALL}\n")
        return
    _banner()
    db = _get_db(args)

    vendors_data = []
    for vendor in db.list_vendors():
        vendors_data.append(_get_vendor_report_data(db, vendor))

    output = "./reports/executive_portfolio.pdf"
    os.makedirs(os.path.dirname(output), exist_ok=True)

    path = _gen_executive(
        vendors_data=vendors_data,
        org_name="Healthcare Organization",
        output_path=output,
    )
    print(f"{Fore.GREEN}  \u2713 Executive report generated: {path}{Style.RESET_ALL}\n")


def cmd_report_attestation(args):
    """Generate attestation report PDF."""
    if not HAS_REPORTS:
        print(f"{Fore.YELLOW}  Reports module not yet available. It is being built separately.{Style.RESET_ALL}\n")
        return
    _banner()
    db = _get_db(args)
    vendor = _find_vendor(db, args.vendor_id)
    if not vendor:
        return

    data = _get_vendor_report_data(db, vendor)
    output = f"./reports/attestation_{vendor.name.lower().replace(' ', '_')}.pdf"
    os.makedirs(os.path.dirname(output), exist_ok=True)

    path = _gen_attestation(
        vendor=data["vendor"],
        verification=data["verification"],
        assessment=data["assessment"],
        baa=data["baa"],
        output_path=output,
    )
    print(f"{Fore.GREEN}  \u2713 Attestation report generated: {path}{Style.RESET_ALL}\n")


def cmd_report_remediation(args):
    """Generate remediation tracker PDF."""
    if not HAS_REPORTS:
        print(f"{Fore.YELLOW}  Reports module not yet available. It is being built separately.{Style.RESET_ALL}\n")
        return
    _banner()
    db = _get_db(args)

    vendors_findings_data = []
    for vendor in db.list_vendors():
        assessments = db.list_assessments(vendor_id=vendor.id)
        all_findings = []
        for a in assessments:
            if a.status == AssessmentStatus.COMPLETED:
                all_findings.extend(a.findings)
        if all_findings:
            vendors_findings_data.append({
                "vendor": vendor,
                "findings": all_findings,
            })

    output = "./reports/remediation_tracker.pdf"
    os.makedirs(os.path.dirname(output), exist_ok=True)

    path = _gen_remediation(
        vendors_findings_data=vendors_findings_data,
        org_name="Healthcare Organization",
        output_path=output,
    )
    print(f"{Fore.GREEN}  \u2713 Remediation report generated: {path}{Style.RESET_ALL}\n")


# ============================================================================
# Command: dashboard (org-wide)
# ============================================================================

def cmd_dashboard(args):
    """Org-wide text dashboard."""
    _banner()
    db = _get_db(args)

    vendors = db.list_vendors()
    if not vendors:
        print(f"  {Fore.YELLOW}No data. Run {Style.BRIGHT}python run_vrm.py demo{Style.RESET_ALL}"
              f"{Fore.YELLOW} to generate demo data.{Style.RESET_ALL}\n")
        return

    _section("Organization Dashboard")

    # Tier counts
    tier_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_score = 0.0
    scored_count = 0
    all_findings_critical = 0
    all_findings_high = 0
    all_findings_medium = 0
    all_findings_low = 0

    vendor_risk_list = []

    for vendor in vendors:
        tier_counts[vendor.tier.value] = tier_counts.get(vendor.tier.value, 0) + 1

        assessments = db.list_assessments(vendor_id=vendor.id)
        latest = None
        for a in reversed(assessments):
            if a.status == AssessmentStatus.COMPLETED:
                latest = a
                break

        score = latest.overall_score if latest else None
        if score is not None:
            total_score += score
            scored_count += 1

        if latest:
            for f in latest.findings:
                if f.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS):
                    if f.severity == FindingSeverity.CRITICAL:
                        all_findings_critical += 1
                    elif f.severity == FindingSeverity.HIGH:
                        all_findings_high += 1
                    elif f.severity == FindingSeverity.MEDIUM:
                        all_findings_medium += 1
                    elif f.severity == FindingSeverity.LOW:
                        all_findings_low += 1

        vendor_risk_list.append({
            "name": vendor.name,
            "tier": vendor.tier.value,
            "score": score,
        })

    avg_score = total_score / scored_count if scored_count > 0 else 0

    # Vendor tier summary
    print(f"  {Style.BRIGHT}Vendors by Risk Tier:{Style.RESET_ALL}")
    for tier_name, color in [
        ("critical", Fore.RED + Style.BRIGHT),
        ("high", Fore.YELLOW),
        ("medium", Fore.CYAN),
        ("low", Fore.GREEN),
    ]:
        count = tier_counts.get(tier_name, 0)
        bar = "█" * (count * 5)
        print(f"    {color}{tier_name.upper():<10}{Style.RESET_ALL}  {bar}  {count}")

    print(f"\n  {Style.BRIGHT}Total Vendors:{Style.RESET_ALL}    {len(vendors)}")
    print(f"  {Style.BRIGHT}Average Score:{Style.RESET_ALL}    {_score_color(avg_score)}{avg_score:.1f}/100{Style.RESET_ALL}")

    # Findings summary
    print(f"\n  {Style.BRIGHT}Open Findings:{Style.RESET_ALL}")
    total_findings = all_findings_critical + all_findings_high + all_findings_medium + all_findings_low
    if total_findings > 0:
        print(f"    {Fore.RED}{Style.BRIGHT}Critical:{Style.RESET_ALL}  {all_findings_critical}")
        print(f"    {Fore.YELLOW}{Style.BRIGHT}High:{Style.RESET_ALL}      {all_findings_high}")
        print(f"    {Fore.YELLOW}Medium:{Style.RESET_ALL}    {all_findings_medium}")
        print(f"    {Fore.WHITE}Low:{Style.RESET_ALL}       {all_findings_low}")
    else:
        print(f"    {Fore.GREEN}No open findings{Style.RESET_ALL}")

    # BAA status
    baa_summary = get_baa_summary(db)
    print(f"\n  {Style.BRIGHT}BAA Status:{Style.RESET_ALL}")
    status_bd = baa_summary.get("status_breakdown", {})
    print(f"    {Fore.GREEN}Active:{Style.RESET_ALL}        {baa_summary['active_baas']}")
    print(f"    {Fore.GREEN}Compliant:{Style.RESET_ALL}     {baa_summary['fully_compliant']}")
    print(f"    {Fore.YELLOW}Needs Amend:{Style.RESET_ALL}  {baa_summary['needs_amendment']}")
    exp_90 = baa_summary.get("expiring_within_90_days", 0)
    if exp_90 > 0:
        print(f"    {Fore.YELLOW}Expiring (90d):{Style.RESET_ALL} {exp_90}")
    expired = baa_summary.get("expired", 0)
    if expired > 0:
        print(f"    {Fore.RED}Expired:{Style.RESET_ALL}      {expired}")

    # Verification summary
    v_report = get_verification_status_report(db)
    print(f"\n  {Style.BRIGHT}Verification:{Style.RESET_ALL}")
    v_bd = v_report["status_breakdown"]
    print(f"    {Fore.GREEN}Verified:{Style.RESET_ALL}      {v_bd.get('verified', 0)}")
    print(f"    {Fore.YELLOW}Pending:{Style.RESET_ALL}       {v_bd.get('pending', 0)}")
    overdue_v = v_bd.get("overdue", 0)
    never_v = v_bd.get("never_verified", 0)
    failed_v = v_bd.get("failed", 0)
    if overdue_v > 0:
        print(f"    {Fore.RED}Overdue:{Style.RESET_ALL}       {overdue_v}")
    if never_v > 0:
        print(f"    {Fore.RED}Never Verified:{Style.RESET_ALL} {never_v}")
    if failed_v > 0:
        print(f"    {Fore.RED}Failed:{Style.RESET_ALL}        {failed_v}")
    print(f"    {Style.BRIGHT}Compliance:{Style.RESET_ALL}    {_score_color(v_report['compliance_percentage'])}{v_report['compliance_percentage']:.1f}%{Style.RESET_ALL}")

    # Top 5 highest risk
    vendor_risk_list.sort(key=lambda v: v["score"] if v["score"] is not None else -1)
    top5 = vendor_risk_list[:5]

    print(f"\n  {Style.BRIGHT}Top 5 Highest Risk Vendors:{Style.RESET_ALL}")
    for v in top5:
        tc = _tier_color(v["tier"])
        score_str = f"{v['score']:.1f}" if v["score"] is not None else "N/A"
        sc = _score_color(v["score"]) if v["score"] is not None else Fore.WHITE
        print(f"    {tc}{v['tier'].upper():<10}{Style.RESET_ALL} {sc}{score_str:>5}{Style.RESET_ALL}  {v['name']}")

    print()


# ============================================================================
# Command: alerts
# ============================================================================

def cmd_alerts(args):
    """Show all actionable alerts across the organization."""
    _banner()
    db = _get_db(args)

    _section("Actionable Alerts")

    # BAA alerts
    baa_alerts = get_baa_alerts(db)
    if baa_alerts:
        print(f"  {Style.BRIGHT}BAA Alerts ({len(baa_alerts)}):{Style.RESET_ALL}\n")
        for alert in baa_alerts:
            color = _severity_color(alert["severity"])
            print(f"    {color}{_badge(alert['severity'], color)}{Style.RESET_ALL} {alert['message']}")
            print(f"           Action: {alert['action']}")
            print()

    # Overdue assessments
    overdue = get_overdue_assessments(db)
    if overdue:
        print(f"  {Style.BRIGHT}Overdue Assessments ({len(overdue)}):{Style.RESET_ALL}\n")
        for item in overdue:
            color = _severity_color(item["urgency"])
            print(f"    {color}{_badge(item['urgency'], color)}{Style.RESET_ALL} {item['vendor_name']} — {item['reason']}")
            print()

    # Overdue verifications
    overdue_v = get_overdue_verifications(db)
    if overdue_v:
        print(f"  {Style.BRIGHT}Overdue Verifications ({len(overdue_v)}):{Style.RESET_ALL}\n")
        for item in overdue_v:
            color = _severity_color(item["urgency"])
            print(f"    {color}{_badge(item['urgency'], color)}{Style.RESET_ALL} {item['vendor_name']} — {item['reason']}")
            print()

    # Vendors needing verification
    needing = get_vendors_needing_verification(db)
    if needing:
        print(f"  {Style.BRIGHT}Vendors Needing Verification ({len(needing)}):{Style.RESET_ALL}\n")
        for item in needing:
            color = _severity_color(item["urgency"])
            print(f"    {color}{_badge(item['urgency'], color)}{Style.RESET_ALL} {item['vendor_name']} — {item['reason']}")
            print()

    if not any([baa_alerts, overdue, overdue_v, needing]):
        print(f"  {Fore.GREEN}No actionable alerts — all clear.{Style.RESET_ALL}\n")


# ============================================================================
# Command: export
# ============================================================================

def cmd_export(args):
    """Export all data as JSON."""
    _banner()
    db = _get_db(args)
    output = getattr(args, "output", None)
    path = db.export_all(export_path=output)
    print(f"  {Fore.GREEN}{Style.BRIGHT}✓ Data exported to: {path}{Style.RESET_ALL}\n")


# ============================================================================
# Command: import
# ============================================================================

def cmd_import(args):
    """Import data from JSON."""
    _banner()
    db = _get_db(args)
    filepath = args.file

    if not os.path.exists(filepath):
        print(f"{Fore.RED}  File not found: {filepath}{Style.RESET_ALL}\n")
        return

    overwrite = getattr(args, "overwrite", False)
    counts = db.import_all(filepath, overwrite=overwrite)

    print(f"  {Fore.GREEN}{Style.BRIGHT}✓ Data imported from: {filepath}{Style.RESET_ALL}")
    for entity, count in counts.items():
        print(f"    {entity}: {count} records")
    print()


# ============================================================================
# Argument parser
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    """Build the complete CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="run_vrm",
        description=f"{BRAND} — CLI Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python run_vrm.py demo                         Generate demo organization\n"
            "  python run_vrm.py vendor list                  List all vendors by risk\n"
            "  python run_vrm.py vendor dashboard <id>        Vendor dashboard\n"
            "  python run_vrm.py assess <vendor_id>           Interactive assessment\n"
            "  python run_vrm.py baa alerts                   BAA compliance alerts\n"
            "  python run_vrm.py dashboard                    Org-wide dashboard\n"
            "  python run_vrm.py alerts                       All actionable alerts\n"
        ),
    )
    parser.add_argument(
        "--data-dir", "-d", default=DEFAULT_DATA_DIR,
        help="Data directory for JSON storage (default: ./data)"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- demo ---
    sp_demo = subparsers.add_parser("demo", help="Generate demo org with 8 vendors")
    sp_demo.set_defaults(func=cmd_demo)

    # --- vendor ---
    sp_vendor = subparsers.add_parser("vendor", help="Vendor management commands")
    vendor_sub = sp_vendor.add_subparsers(dest="vendor_command")

    sp_vendor_add = vendor_sub.add_parser("add", help="Interactive vendor onboarding")
    sp_vendor_add.set_defaults(func=cmd_vendor_add)

    sp_vendor_list = vendor_sub.add_parser("list", help="List all vendors by risk")
    sp_vendor_list.set_defaults(func=cmd_vendor_list)

    sp_vendor_dash = vendor_sub.add_parser("dashboard", help="Vendor dashboard")
    sp_vendor_dash.add_argument("vendor_id", help="Vendor ID or name")
    sp_vendor_dash.set_defaults(func=cmd_vendor_dashboard)

    sp_vendor_off = vendor_sub.add_parser("offboard", help="Offboard a vendor")
    sp_vendor_off.add_argument("vendor_id", help="Vendor ID or name")
    sp_vendor_off.set_defaults(func=cmd_vendor_offboard)

    # --- baa ---
    sp_baa = subparsers.add_parser("baa", help="BAA management commands")
    baa_sub = sp_baa.add_subparsers(dest="baa_command")

    sp_baa_create = baa_sub.add_parser("create", help="Create new BAA")
    sp_baa_create.add_argument("vendor_id", help="Vendor ID or name")
    sp_baa_create.set_defaults(func=cmd_baa_create)

    sp_baa_list = baa_sub.add_parser("list", help="List all BAAs")
    sp_baa_list.set_defaults(func=cmd_baa_list)

    sp_baa_alerts = baa_sub.add_parser("alerts", help="Show BAA alerts")
    sp_baa_alerts.set_defaults(func=cmd_baa_alerts)

    sp_baa_check = baa_sub.add_parser("check", help="Check BAA compliance")
    sp_baa_check.add_argument("baa_id", help="BAA ID")
    sp_baa_check.set_defaults(func=cmd_baa_check)

    # --- assess ---
    sp_assess = subparsers.add_parser("assess", help="Run vendor assessment")
    assess_sub = sp_assess.add_subparsers(dest="assess_command")

    # Default assess (interactive) — also handle `assess <vendor_id>` directly
    sp_assess.add_argument("vendor_id", nargs="?", help="Vendor ID or name")
    sp_assess.set_defaults(func=cmd_assess)

    sp_assess_quick = assess_sub.add_parser("quick", help="Quick demo assessment")
    sp_assess_quick.add_argument("vendor_id", help="Vendor ID or name")
    sp_assess_quick.set_defaults(func=cmd_assess_quick)

    # --- verify ---
    sp_verify = subparsers.add_parser("verify", help="Verification commands")
    verify_sub = sp_verify.add_subparsers(dest="verify_command")

    sp_verify_req = verify_sub.add_parser("request", help="Send verification request")
    sp_verify_req.add_argument("vendor_id", help="Vendor ID or name")
    sp_verify_req.set_defaults(func=cmd_verify_request)

    sp_verify_sub = verify_sub.add_parser("submit", help="Submit verification")
    sp_verify_sub.add_argument("verification_id", help="Verification ID")
    sp_verify_sub.set_defaults(func=cmd_verify_submit)

    sp_verify_stat = verify_sub.add_parser("status", help="Org-wide verification status")
    sp_verify_stat.set_defaults(func=cmd_verify_status)

    # --- report ---
    sp_report = subparsers.add_parser("report", help="Generate PDF reports")
    report_sub = sp_report.add_subparsers(dest="report_command")

    sp_rc = report_sub.add_parser("risk-card", help="Vendor risk card PDF")
    sp_rc.add_argument("vendor_id", help="Vendor ID or name")
    sp_rc.set_defaults(func=cmd_report_risk_card)

    sp_exec = report_sub.add_parser("executive", help="Executive portfolio PDF")
    sp_exec.set_defaults(func=cmd_report_executive)

    sp_att = report_sub.add_parser("attestation", help="Attestation report PDF")
    sp_att.add_argument("vendor_id", help="Vendor ID or name")
    sp_att.set_defaults(func=cmd_report_attestation)

    sp_rem = report_sub.add_parser("remediation", help="Remediation tracker PDF")
    sp_rem.set_defaults(func=cmd_report_remediation)

    # --- dashboard ---
    sp_dash = subparsers.add_parser("dashboard", help="Org-wide text dashboard")
    sp_dash.set_defaults(func=cmd_dashboard)

    # --- alerts ---
    sp_alerts = subparsers.add_parser("alerts", help="All actionable alerts")
    sp_alerts.set_defaults(func=cmd_alerts)

    # --- export ---
    sp_export = subparsers.add_parser("export", help="Export all data as JSON")
    sp_export.add_argument("-o", "--output", help="Output file path")
    sp_export.set_defaults(func=cmd_export)

    # --- import ---
    sp_import = subparsers.add_parser("import", help="Import data from JSON")
    sp_import.add_argument("file", help="JSON file to import")
    sp_import.add_argument("--overwrite", action="store_true", help="Overwrite existing data")
    sp_import.set_defaults(func=cmd_import)

    return parser


# ============================================================================
# Main
# ============================================================================

def main():
    """Entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        _banner()
        parser.print_help()
        print()
        return

    # Handle subcommands that need fallback
    func = getattr(args, "func", None)

    if func is None:
        # Check if it's a vendor/baa/verify/report/assess command without subcommand
        if args.command == "vendor":
            print(f"{Fore.YELLOW}  Usage: python run_vrm.py vendor {{add,list,dashboard,offboard}}{Style.RESET_ALL}\n")
        elif args.command == "baa":
            print(f"{Fore.YELLOW}  Usage: python run_vrm.py baa {{create,list,alerts,check}}{Style.RESET_ALL}\n")
        elif args.command == "verify":
            print(f"{Fore.YELLOW}  Usage: python run_vrm.py verify {{request,submit,status}}{Style.RESET_ALL}\n")
        elif args.command == "report":
            print(f"{Fore.YELLOW}  Usage: python run_vrm.py report {{risk-card,executive,attestation,remediation}}{Style.RESET_ALL}\n")
        elif args.command == "assess":
            if args.vendor_id:
                # `assess <vendor_id>` without subcommand → interactive
                cmd_assess(args)
            else:
                print(f"{Fore.YELLOW}  Usage: python run_vrm.py assess <vendor_id> OR assess quick <vendor_id>{Style.RESET_ALL}\n")
        else:
            parser.print_help()
        return

    try:
        func(args)
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}Interrupted.{Style.RESET_ALL}\n")
    except ValueError as e:
        print(f"\n  {Fore.RED}Error: {e}{Style.RESET_ALL}\n")
    except Exception as e:
        print(f"\n  {Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
