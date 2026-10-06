import ipaddress
import re
import socket
import sys
from urllib.parse import urlparse

import requests
import whois
from bs4 import BeautifulSoup
from whois.exceptions import (
    FailedParsingWhoisOutput,
    UnknownTld,
    WhoisCommandFailed,
    WhoisCommandTimeout,
)

MAX_URL_LENGTH = 2048
MAX_RESPONSE_BYTES = 256 * 1024
IP_PATTERN = re.compile(r"^https?://(?:\d{1,3}\.){3}\d{1,3}(?:[:/]|$)")


class URLValidationError(ValueError):
    """Raised when a URL is unsafe or cannot be analyzed."""


def check_ip_in_url(url: str) -> bool:
    return IP_PATTERN.match(url) is not None


def check_at_symbol(url: str) -> bool:
    return "@" in url


def check_url_length(url: str) -> bool:
    return len(url) > 75


def check_hyphen(url: str) -> bool:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return "-" in hostname or "-" in parsed.netloc


def check_https(url: str) -> bool:
    return url.startswith("https://")


def validate_url(url: str) -> str:
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        raise URLValidationError("URL must be between 1 and 2048 characters")

    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None:
        raise URLValidationError("Only HTTPS URLs without user information are supported")
    if parsed.fragment:
        raise URLValidationError("URL fragments are not supported")

    try:
        hostname = parsed.hostname
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None

    if address is not None:
        raise URLValidationError("Private, loopback, link-local, and reserved hosts are not supported")

    if hostname.endswith((".localhost", ".invalid", ".test", ".example", ".internal")):
        raise URLValidationError("Reserved host suffixes are not supported")

    try:
        resolved_addresses = {
            ipaddress.ip_address(result[4][0])
            for result in socket.getaddrinfo(hostname, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        }
    except socket.gaierror as error:
        raise URLValidationError("Host could not be resolved") from error

    if any(
        address.is_private or address.is_loopback or address.is_link_local or address.is_reserved
        for address in resolved_addresses
    ):
        raise URLValidationError("Host resolves to a private or reserved address")

    return url


def check_domain_age(domain: str) -> str:
    try:
        result = whois.query(domain, timeout=5.0)
        if result is None:
            return "WHOIS Failed"
        creation_date = result.creation_date
        if creation_date:
            return "Old or Registered"
        return "Possibly New"
    except (
        FailedParsingWhoisOutput,
        UnknownTld,
        WhoisCommandFailed,
        WhoisCommandTimeout,
        OSError,
        TimeoutError,
    ):
        return "WHOIS Failed"


def check_for_mailto_form(url: str) -> bool | str:
    try:
        response = requests.get(
            url,
            timeout=(3, 10),
            stream=True,
            allow_redirects=False,
            headers={"User-Agent": "phishing-detector/0.1.0"},
        )
        response.raise_for_status()
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_RESPONSE_BYTES:
            return "Page Load Failed"

        content = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            content.extend(chunk)
            if len(content) > MAX_RESPONSE_BYTES:
                return "Page Load Failed"

        soup = BeautifulSoup(content.decode("utf-8", errors="replace"), "html.parser")
        return any("mailto:" in str(form).lower() for form in soup.find_all("form"))
    except (requests.RequestException, ValueError, OSError):
        return "Page Load Failed"


def run_checks(url: str) -> None:
    validated_url = validate_url(url)
    domain = urlparse(validated_url).hostname or ""

    print("\n Scanning:", validated_url)
    print("=======================")
    print(f"1. Uses IP in URL: {'YES' if check_ip_in_url(validated_url) else 'NO'}")
    print(f"2. Contains '@' Symbol: {'YES' if check_at_symbol(validated_url) else 'NO'}")
    print(f"3. URL Length > 75: {'YES' if check_url_length(validated_url) else 'NO'}")
    print(f"4. Hyphen in Domain: {'YES' if check_hyphen(validated_url) else 'NO'}")
    print(f"5. Uses HTTPS: {'YES' if check_https(validated_url) else 'NO'}")
    print(f"6. Domain Age: {check_domain_age(domain)}")
    mailto_form = check_for_mailto_form(validated_url)
    print(f"7. Suspicious Form (mailto:): {'YES' if mailto_form is True else 'NO'}")
    print("=======================")


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python easy_phish_detect.py <https-url>")
        raise SystemExit(1)

    try:
        run_checks(sys.argv[1])
    except URLValidationError as error:
        print(f"Invalid URL: {error}", file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
          

    