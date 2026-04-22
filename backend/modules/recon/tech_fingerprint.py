"""
SentinelX — Technology Fingerprinting
Detects CMS, frameworks, servers, CDNs, and cloud providers.
Maps detected technologies to known CVE patterns.
"""

import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Signature database for technology detection
TECH_SIGNATURES = {
    # CMS
    "WordPress": {
        "signatures": ["wp-content", "wp-includes", "wp-json", "/xmlrpc.php", "WordPress"],
        "category": "cms",
        "version_patterns": [r'content="WordPress\s+([\d.]+)"', r'ver=([\d.]+)'],
    },
    "Drupal": {
        "signatures": ["Drupal", "drupal.js", "sites/default", "/core/misc/drupal.js"],
        "category": "cms",
        "version_patterns": [r'Drupal\s+([\d.]+)'],
    },
    "Joomla": {
        "signatures": ["/media/jui/", "Joomla!", "/administrator/", "joomla"],
        "category": "cms",
        "version_patterns": [r'Joomla!\s+([\d.]+)'],
    },

    # JavaScript Frameworks
    "React": {
        "signatures": ["__NEXT_DATA__", "react-root", "_next/static", "react.production.min.js", "_reactRootContainer"],
        "category": "framework",
    },
    "Next.js": {
        "signatures": ["__NEXT_DATA__", "_next/static", "/_next/"],
        "category": "framework",
        "version_patterns": [r'"version"\s*:\s*"([\d.]+)"'],
    },
    "Angular": {
        "signatures": ["ng-version", "ng-app", "angular.min.js", "ng-controller"],
        "category": "framework",
        "version_patterns": [r'ng-version="([\d.]+)"'],
    },
    "Vue.js": {
        "signatures": ["vue.min.js", "vue.js", "__vue__", "v-app", "vue-router"],
        "category": "framework",
    },
    "jQuery": {
        "signatures": ["jquery.min.js", "jquery.js", "jQuery v"],
        "category": "library",
        "version_patterns": [r'jQuery\s+v([\d.]+)', r'jquery[.-]([\d.]+)'],
    },

    # Backend Frameworks
    "Laravel": {
        "signatures": ["laravel_session", "XSRF-TOKEN", "laravel"],
        "category": "framework",
    },
    "Django": {
        "signatures": ["csrfmiddlewaretoken", "__admin/", "django"],
        "category": "framework",
    },
    "Ruby on Rails": {
        "signatures": ["rails", "_rails", "csrf-token", "action_dispatch"],
        "category": "framework",
    },
    "Express.js": {
        "signatures": ["X-Powered-By: Express"],
        "category": "framework",
    },
    "ASP.NET": {
        "signatures": ["__VIEWSTATE", "asp.net", "X-AspNet-Version", ".aspx"],
        "category": "framework",
        "version_patterns": [r'X-AspNet-Version:\s*([\d.]+)'],
    },

    # Web Servers
    "Nginx": {
        "signatures": ["nginx"],
        "category": "server",
        "version_patterns": [r'nginx/([\d.]+)'],
    },
    "Apache": {
        "signatures": ["Apache"],
        "category": "server",
        "version_patterns": [r'Apache/([\d.]+)'],
    },
    "IIS": {
        "signatures": ["Microsoft-IIS"],
        "category": "server",
        "version_patterns": [r'Microsoft-IIS/([\d.]+)'],
    },
    "LiteSpeed": {
        "signatures": ["LiteSpeed"],
        "category": "server",
        "version_patterns": [r'LiteSpeed/([\d.]+)'],
    },

    # CDN / Cloud
    "Cloudflare": {
        "signatures": ["cf-ray", "__cfduid", "cloudflare", "cf-cache-status"],
        "category": "cdn",
    },
    "AWS CloudFront": {
        "signatures": ["x-amz-cf", "cloudfront", "Via: .+cloudfront"],
        "category": "cdn",
    },
    "AWS S3": {
        "signatures": ["AmazonS3", "x-amz-request-id", "s3.amazonaws.com"],
        "category": "hosting",
    },
    "Google Cloud": {
        "signatures": ["X-Cloud-Trace-Context", "google.com/cloud"],
        "category": "hosting",
    },
    "Vercel": {
        "signatures": ["x-vercel", "vercel", "X-Vercel-Id"],
        "category": "hosting",
    },
    "Netlify": {
        "signatures": ["x-nf-request-id", "netlify"],
        "category": "hosting",
    },

    # Analytics / Marketing
    "Google Analytics": {
        "signatures": ["google-analytics.com", "gtag", "ga.js", "analytics.js", "G-", "UA-"],
        "category": "analytics",
    },
    "Google Tag Manager": {
        "signatures": ["googletagmanager.com", "GTM-"],
        "category": "analytics",
    },
}


async def fingerprint_technologies(domain: str) -> dict[str, Any]:
    """
    Detect technologies used by the target domain.
    Returns categorized tech list with version info where available.
    """
    results = {
        "detected": [],
        "categories": {},
        "findings": [],
    }

    try:
        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
            response = await client.get(f"https://{domain}")
            body = response.text
            headers_str = str(response.headers)
            combined = body + headers_str

            for tech_name, tech_info in TECH_SIGNATURES.items():
                # Check if any signature matches
                detected = False
                for sig in tech_info["signatures"]:
                    if sig.lower() in combined.lower():
                        detected = True
                        break

                if detected:
                    tech_entry = {
                        "name": tech_name,
                        "category": tech_info["category"],
                        "version": None,
                    }

                    # Try to extract version
                    for pattern in tech_info.get("version_patterns", []):
                        match = re.search(pattern, combined, re.IGNORECASE)
                        if match:
                            tech_entry["version"] = match.group(1)
                            break

                    results["detected"].append(tech_entry)

                    # Group by category
                    cat = tech_info["category"]
                    if cat not in results["categories"]:
                        results["categories"][cat] = []
                    results["categories"][cat].append(tech_entry)

            # Generate findings for detected tech with versions
            for tech in results["detected"]:
                if tech["version"]:
                    results["findings"].append({
                        "severity": "info",
                        "title": f"Technology Detected: {tech['name']} v{tech['version']}",
                        "description": (
                            f"Detected {tech['name']} version {tech['version']}. "
                            "Specific version information helps assess exposure to known CVEs."
                        ),
                        "remediation": (
                            f"Ensure {tech['name']} is updated to the latest version. "
                            "Check for known vulnerabilities at nvd.nist.gov."
                        ),
                        "category": "technology",
                    })

            # Check for outdated/vulnerable patterns
            _check_vulnerable_tech(results, combined)

    except Exception as e:
        logger.error(f"Tech fingerprinting failed for {domain}: {e}")
        results["findings"].append({
            "severity": "info",
            "title": "Technology Fingerprinting Error",
            "description": str(e),
            "category": "error",
        })

    return results


def _check_vulnerable_tech(results: dict, page_content: str):
    """Check for commonly vulnerable configurations."""
    combined_lower = page_content.lower()

    # WordPress-specific checks
    if any(t["name"] == "WordPress" for t in results["detected"]):
        if "wp-json/wp/v2/users" in combined_lower or "/wp-json/" in combined_lower:
            results["findings"].append({
                "severity": "medium",
                "title": "WordPress REST API User Enumeration",
                "description": (
                    "WordPress REST API is publicly accessible and may allow "
                    "enumeration of user accounts, revealing usernames for brute-force attacks."
                ),
                "remediation": "Restrict access to wp-json/wp/v2/users or disable REST API user enumeration.",
                "category": "technology",
            })

        if "xmlrpc.php" in combined_lower:
            results["findings"].append({
                "severity": "medium",
                "title": "WordPress XML-RPC Enabled",
                "description": (
                    "XML-RPC is enabled, which can be used for brute-force attacks "
                    "(system.multicall) and DDoS amplification (pingback)."
                ),
                "remediation": "Disable XML-RPC if not needed, or block access to xmlrpc.php.",
                "category": "technology",
            })

    # Exposed debug/development indicators
    debug_indicators = [
        ("DJANGO_DEBUG", "Django debug mode indicator found"),
        ("debug_toolbar", "Debug toolbar detected"),
        ("phpMyAdmin", "phpMyAdmin detected — database admin exposed"),
        ("adminer.php", "Adminer database tool detected"),
        ("elmah.axd", "ELMAH error log exposed (ASP.NET)"),
    ]

    for indicator, description in debug_indicators:
        if indicator.lower() in combined_lower:
            results["findings"].append({
                "severity": "high",
                "title": f"Development/Debug Tool Exposed: {indicator}",
                "description": description + ". This should never be accessible in production.",
                "remediation": f"Remove or restrict access to {indicator} in production environments.",
                "category": "technology",
            })
