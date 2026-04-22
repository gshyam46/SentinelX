"""
SentinelX - Report Generator and Orchestrator
Aggregates findings and generates JSON reports and prepares for PDF rendering.
"""

import logging
from typing import Dict, Any

logger = logging.getLogger("sentinelx.report_generator")

def generate_json_report(scan_data: Dict[str, Any], user_tier: str = "free") -> Dict[str, Any]:
    """
    Creates a clean JSON structure suitable for frontend consumption
    and metadata injection for the PDF.
    
    If user_tier is 'free', blurs out the majority of detailed findings.
    """
    
    findings = scan_data.get("all_findings", [])
    summary = scan_data.get("summary", {})
    
    # Base structure
    report = {
        "status": "ready",
        "metadata": {
            "scan_type": summary.get("scan_type", "unknown"),
            "target": summary.get("target", "unknown"),
            "risk_score": summary.get("risk_score", 0),
            "total_findings": len(findings)
        },
        "severity_distribution": summary.get("severity_counts", {}),
        "executive_summary": "Scan completed successfully. ",
        "findings": []
    }
    
    if report["metadata"]["risk_score"] > 80:
        report["executive_summary"] += "The target is critically vulnerable. Immediate action is required."
    elif report["metadata"]["risk_score"] > 50:
        report["executive_summary"] += "The target has severe exposures. Remediate high and medium findings rapidly."
    elif report["metadata"]["risk_score"] > 20:
        report["executive_summary"] += "The target exhibits average security posture. Pay attention to configuration enhancements."
    else:
        report["executive_summary"] += "The target maintains a strong security posture with few issues detected."

    # Parse findings
    if user_tier == "free":
        # Gate free tier - show 2 full findings
        visible = findings[:2]
        hidden_count = len(findings) - 2
        
        report["findings"].extend(visible)
        
        for hidden in findings[2:]:
            report["findings"].append({
                "title": "🔒 " + str(hidden.get("title", ""))[:30] + "...",
                "severity": hidden.get("severity"),
                "gated": True,
                "description": "Upgrade to SentinelX Pro to unlock full details for this finding."
            })
            
        report["upsell_cta"] = f"{hidden_count} additional findings are hidden. Upgrade to Pro for complete visibility and active remediation steps."
    else:
        # Paid tier sees everything
        report["findings"] = findings
        
    return report

