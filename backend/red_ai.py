import asyncio
import time

import httpx


ARENA_URL = "http://arena-web/"

SECURITY_HEADERS = {
    "content-security-policy": "Helps reduce content injection risks",
    "x-frame-options": "Helps protect against clickjacking",
    "x-content-type-options": "Helps prevent MIME type sniffing",
    "strict-transport-security": "Enforces HTTPS connections",
    "referrer-policy": "Controls referrer information sharing"
}


async def run_reconnaissance():
    """
    Performs HTTP reconnaissance and basic security
    header inspection against the isolated Cyber Mirror Arena.
    """

    start_time = time.perf_counter()

    try:
        timeout = httpx.Timeout(5.0)

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False
        ) as client:

            response = await asyncio.wait_for(
                client.get(ARENA_URL),
                timeout=6.0
            )

        elapsed_time = round(
            time.perf_counter() - start_time, 3
        )

        # Collect server information
        server = response.headers.get(
            "server", "Unknown"
        )

        content_type = response.headers.get(
            "content-type", "Unknown"
        )

        # Inspect security headers
        header_findings = []

        for header, description in SECURITY_HEADERS.items():

            # HSTS is applicable to HTTPS responses
            if (
                header == "strict-transport-security"
                and response.url.scheme != "https"
            ):
                header_findings.append({
                    "header": header,
                    "status": "not_applicable",
                    "value": None,
                    "description": "HSTS applies to HTTPS responses"
                })
                continue

            value = response.headers.get(header)

            if value:
                header_findings.append({
                    "header": header,
                    "status": "present",
                    "value": value,
                    "description": description
                })

            else:
                header_findings.append({
                    "header": header,
                    "status": "missing",
                    "value": None,
                    "description": description
                })

        # Categorize findings
        missing_headers = [
            item["header"]
            for item in header_findings
            if item["status"] == "missing"
        ]

        present_headers = [
            item["header"]
            for item in header_findings
            if item["status"] == "present"
        ]

        not_applicable_headers = [
            item["header"]
            for item in header_findings
            if item["status"] == "not_applicable"
        ]

        applicable_headers = (
            len(present_headers) + len(missing_headers)
        )

        return {
            "target": "arena-web",
            "action": "HTTP reconnaissance and security header inspection",
            "status": "completed",

            "http_status": response.status_code,
            "server": server,
            "content_type": content_type,
            "response_size": len(response.content),
            "response_time": elapsed_time,

            "security_headers": header_findings,

            "missing_security_headers": missing_headers,

            "total_headers_checked": applicable_headers,
            "headers_present": len(present_headers),
            "headers_missing": len(missing_headers),
            "headers_not_applicable": len(not_applicable_headers)
        }

    except asyncio.TimeoutError:

        return {
            "target": "arena-web",
            "action": "HTTP reconnaissance",
            "status": "timeout",
            "error": "Arena request exceeded time limit"
        }

    except httpx.RequestError as error:

        return {
            "target": "arena-web",
            "action": "HTTP reconnaissance",
            "status": "failed",
            "error": str(error)
        }