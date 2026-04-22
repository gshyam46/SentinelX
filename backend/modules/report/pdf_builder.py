"""
SentinelX - PDF Builder Module
Uses WeasyPrint to generate PDF reports from HTML templates.
"""

import logging
import os
import tempfile
from typing import Dict, Any

try:
    from weasyprint import HTML, CSS
except ImportError:
    HTML = None
    CSS = None

logger = logging.getLogger("sentinelx.pdf_builder")

def build_pdf_report(report_data: Dict[str, Any]) -> str:
    """
    Takes JSON report data, renders it into a clean HTML template,
    and returns the system path to the generated PDF file.
    """
    if HTML is None:
        logger.error("WeasyPrint is not installed or missing system dependencies (GTK3/Pango).")
        # In a real app we'd fallback to reportlab or return None
        # Returning a mock pdf path for dev/demo parity
        temp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        temp.write(b"%PDF-1.4\n%Missing Weasyprint Engine")
        temp.close()
        return temp.name

    # Create a basic inner HTML template string to avoid file path complexity
    html_content = _generate_html(report_data)
    
    # Render with WeasyPrint
    try:
        temp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        
        # We can add a basic CSS styling string
        css_content = CSS(string='''
            @page { size: A4; margin: 2cm; }
            body { font-family: 'Helvetica', Arial, sans-serif; color: #333; line-height: 1.6; }
            .header { text-align: center; border-bottom: 2px solid #00f0ff; padding-bottom: 20px; margin-bottom: 40px; }
            .title { color: #0a0e17; font-size: 28px; font-weight: bold; }
            .subtitle { color: #8b9bb4; font-size: 16px; margin-top: 10px; }
            .section { margin-bottom: 30px; }
            .risk-critical { color: #ff2a5f; font-weight: bold; }
            .risk-high { color: #ff8c00; font-weight: bold; }
            .finding-card { border: 1px solid #ddd; padding: 15px; border-radius: 8px; margin-bottom: 15px; page-break-inside: avoid; }
            .finding-title { font-size: 16px; font-weight: bold; margin-bottom: 10px; display: flex; justify-content: space-between; }
            .gated-card { background-color: #f8f9fa; border: 1px dashed #ccc; text-align: center; }
        ''')
        
        HTML(string=html_content).write_pdf(temp.name, stylesheets=[css_content])
        return temp.name
    except Exception as e:
        logger.error(f"Failed to generate PDF with Weasyprint: {e}")
        return None

def _generate_html(data: Dict[str, Any]) -> str:
    """Helper to construct the HTML string for injection."""
    metadata = data.get("metadata", {})
    findings = data.get("findings", [])
    
    # Findings HTML
    findings_html = ""
    for f in findings:
        if f.get("gated"):
            findings_html += f"""
            <div class="finding-card gated-card">
                <div class="finding-title">{f.get('title')}</div>
                <p>{f.get('description')}</p>
            </div>
            """
        else:
            findings_html += f"""
            <div class="finding-card">
                <div class="finding-title">
                    <span>{f.get('title')}</span>
                    <span style="text-transform: uppercase; font-size: 12px; padding: 3px 8px; border-radius: 4px; background: #eee;">{f.get('severity')}</span>
                </div>
                <p><strong>Description:</strong> {f.get('description')}</p>
                <p><strong>Remediation:</strong> {f.get('remediation', 'N/A')}</p>
            </div>
            """
            
    # Executive Summary HTML
    html = f"""
    <html>
    <body>
        <div class="header">
            <div class="title">SentinelX Security Report</div>
            <div class="subtitle">Target: {metadata.get('target', 'Unknown')} | Type: {metadata.get('scan_type')}</div>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>{data.get('executive_summary', 'No summary available.')}</p>
            <p><strong>Overall Risk Score:</strong> {metadata.get('risk_score', '0')}/100</p>
            <p><strong>Total Findings:</strong> {metadata.get('total_findings', '0')}</p>
        </div>
        
        <div class="section">
            <h2>Detailed Findings</h2>
            {findings_html}
        </div>
        
        {"<p style='color:#7000ff; text-align:center; font-weight:bold; margin-top:40px;'>" + data.get('upsell_cta') + "</p>" if data.get('upsell_cta') else ""}
    </body>
    </html>
    """
    return html
