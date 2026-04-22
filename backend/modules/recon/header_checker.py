"""
SentinelX — HTTP Security Header Checker
Audits OWASP recommended security headers, cookie flags, and CORS config.
"""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# OWASP Recommended Security Headers
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "title": "Missing HSTS (HTTP Strict Transport Security)",
        "description": (
            "Without HSTS, browsers may connect over insecure HTTP first, "
            "allowing man-in-the-middle attackers to intercept or downgrade the connection. "
            "This enables session hijacking and credential theft."
        ),
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "title": "Missing Content Security Policy (CSP)",
        "description": (
            "Without CSP, the browser has no restrictions on what scripts, styles, and resources "
            "can load. This significantly increases the attack surface for XSS attacks."
        ),
        "remediation": (
            "Add a Content-Security-Policy header. Start with:\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        ),
    },
    "X-Frame-Options": {
        "severity": "medium",
        "title": "Missing X-Frame-Options (Clickjacking Protection)",
        "description": (
            "The page can be embedded in iframes on other sites. "
            "Attackers can overlay invisible UI on top of your page "
            "to trick users into clicking buttons they didn't intend to (clickjacking)."
        ),
        "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if iframes are needed)",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "title": "Missing X-Content-Type-Options",
        "description": (
            "Without 'nosniff', browsers may MIME-sniff response content. "
            "This can allow attackers to trick the browser into treating uploaded files "
            "as executable scripts."
        ),
        "remediation": "Add header: X-Content-Type-Options: nosniff",
    },
    "Permissions-Policy": {
        "severity": "low",
        "title": "Missing Permissions-Policy",
        "description": (
            "No Permissions-Policy (formerly Feature-Policy) is set. "
            "Sensitive browser features like camera, microphone, and geolocation "
            "are not restricted."
        ),
        "remediation": (
            "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()"
        ),
    },
    "Referrer-Policy": {
        "severity": "low",
        "title": "Missing Referrer-Policy",
        "description": (
            "Without a Referrer-Policy, the full URL (potentially including sensitive "
            "query parameters) may be leaked to third-party sites via the Referer header."
        ),
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "X-XSS-Protection": {
        "severity": "info",
        "title": "Missing X-XSS-Protection",
        "description": (
            "While largely superseded by CSP, X-XSS-Protection provides a fallback "
            "for older browsers that don't support CSP."
        ),
        "remediation": "Add header: X-XSS-Protection: 1; mode=block",
    },
}


async def check_headers(domain: str) -> dict[str, Any]:
    """
    Audit HTTP security headers against OWASP recommendations.
    Also checks server info disclosure, cookie flags, and CORS.
    """
    results = {
        "headers_present": {},
        "headers_missing": [],
        "server_info": {},
        "cookies": [],
        "cors": {},
        "findings": [],
    }

    try:
        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
            # Check HTTPS version
            response = await client.get(f"https://{domain}")
            headers = dict(response.headers)
            results["headers_present"] = headers

            # 1. Check security headers
            for header_name, header_info in SECURITY_HEADERS.items():
                if header_name.lower() not in {k.lower(): k for k in headers}:
                    results["headers_missing"].append(header_name)
                    results["findings"].append({
                        "severity": header_info["severity"],
                        "title": header_info["title"],
                        "description": header_info["description"],
                        "remediation": header_info["remediation"],
                        "category": "http_headers",
                    })

            # 2. Server information disclosure
            server = headers.get("server", headers.get("Server", ""))
            x_powered = headers.get("x-powered-by", headers.get("X-Powered-By", ""))

            if server:
                results["server_info"]["server"] = server
                results["findings"].append({
                    "severity": "low",
                    "title": f"Server Version Disclosed: {server}",
                    "description": (
                        f"The Server header reveals '{server}'. "
                        "Attackers use this to find known vulnerabilities for the specific "
                        "server software and version."
                    ),
                    "remediation": "Remove or obfuscate the Server header in your web server configuration.",
                    "category": "information_disclosure",
                })

            if x_powered:
                results["server_info"]["x_powered_by"] = x_powered
                results["findings"].append({
                    "severity": "low",
                    "title": f"Technology Disclosed: X-Powered-By: {x_powered}",
                    "description": (
                        f"The X-Powered-By header reveals '{x_powered}'. "
                        "This helps attackers identify the technology stack and target known exploits."
                    ),
                    "remediation": "Remove the X-Powered-By header from server responses.",
                    "category": "information_disclosure",
                })

            # 3. Cookie security analysis
            set_cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, 'get_list') else []
            # Fallback for httpx headers
            if not set_cookies:
                set_cookies = [v for k, v in response.headers.multi_items() if k.lower() == "set-cookie"]

            for cookie_str in set_cookies:
                cookie_flags = cookie_str.lower()
                cookie_name = cookie_str.split("=")[0].strip() if "=" in cookie_str else "unknown"

                cookie_info = {"name": cookie_name, "issues": []}

                if "secure" not in cookie_flags:
                    cookie_info["issues"].append("missing_secure")
                    results["findings"].append({
                        "severity": "medium",
                        "title": f"Cookie '{cookie_name}' Missing Secure Flag",
                        "description": (
                            "Cookie can be transmitted over unencrypted HTTP connections, "
                            "allowing attackers to intercept it via man-in-the-middle attacks."
                        ),
                        "remediation": f"Add the Secure flag to the '{cookie_name}' cookie.",
                        "category": "cookie_security",
                    })

                if "httponly" not in cookie_flags:
                    cookie_info["issues"].append("missing_httponly")
                    results["findings"].append({
                        "severity": "medium",
                        "title": f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                        "description": (
                            "Cookie is accessible via JavaScript. If an XSS vulnerability exists, "
                            "attackers can steal this cookie to hijack user sessions."
                        ),
                        "remediation": f"Add the HttpOnly flag to the '{cookie_name}' cookie.",
                        "category": "cookie_security",
                    })

                if "samesite" not in cookie_flags:
                    cookie_info["issues"].append("missing_samesite")

                results["cookies"].append(cookie_info)

            # 4. CORS analysis
            cors_header = headers.get("access-control-allow-origin",
                                       headers.get("Access-Control-Allow-Origin", ""))
            if cors_header:
                results["cors"]["allow_origin"] = cors_header
                if cors_header == "*":
                    results["findings"].append({
                        "severity": "medium",
                        "title": "CORS Allows All Origins (Access-Control-Allow-Origin: *)",
                        "description": (
                            "Any website can make requests to your API and read the responses. "
                            "If the API handles sensitive data or authentication, this is exploitable."
                        ),
                        "remediation": "Restrict Access-Control-Allow-Origin to specific trusted domains.",
                        "category": "cors",
                    })

            # 5. Check if HTTP redirects to HTTPS
            try:
                http_response = await client.get(f"http://{domain}", follow_redirects=False)
                if http_response.status_code not in (301, 302, 307, 308):
                    results["findings"].append({
                        "severity": "medium",
                        "title": "HTTP Does Not Redirect to HTTPS",
                        "description": (
                            "The HTTP version of the site does not redirect to HTTPS. "
                            "Users who type the URL without 'https://' will connect insecurely."
                        ),
                        "remediation": "Configure a 301 redirect from HTTP to HTTPS on your web server.",
                        "category": "http_headers",
                    })
                elif http_response.status_code in (301, 302, 307, 308):
                    location = http_response.headers.get("location", "")
                    if location and not location.startswith("https://"):
                        results["findings"].append({
                            "severity": "medium",
                            "title": "HTTP Redirect Not to HTTPS",
                            "description": f"HTTP redirects to {location} instead of HTTPS.",
                            "remediation": "Ensure HTTP redirects to the HTTPS version of the site.",
                            "category": "http_headers",
                        })
            except Exception:
                pass

    except httpx.ConnectError:
        results["findings"].append({
            "severity": "info",
            "title": "HTTPS Connection Failed",
            "description": f"Could not connect to https://{domain} — host may be down or not serving HTTPS.",
            "category": "connectivity",
        })
    except Exception as e:
        logger.error(f"Header check failed for {domain}: {e}")
        results["findings"].append({
            "severity": "info",
            "title": "Header Check Error",
            "description": str(e),
            "category": "error",
        })

    return results
