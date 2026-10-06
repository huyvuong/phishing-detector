# Phishing Detector

A small, dependency-light command-line detector for basic phishing indicators in HTTPS URLs. It is intended as a safety-oriented heuristic tool, not a definitive phishing verdict.

## Features

- Requires HTTPS and rejects user information, private/reserved addresses, and unsafe URL forms.
- Blocks redirects and limits the downloaded page size.
- Uses the Python WHOIS library instead of shell commands.
- Has no credential handling and does not send submitted URLs to a remote service.
- Includes automated tests for validation and detection rules.

## Installation

```bash
uv sync
uv run phishing-detector https://example.com
```

The executable also accepts a URL as its only argument:

```bash
uv run python easy_phish_detect.py https://example.com
```

## Security notes

This tool is a heuristic and should not be treated as proof that a URL is safe or malicious. It does not follow redirects, does not expose credentials, and does not upload URLs or responses. Review any URL with a trusted browser, email provider, or security team before interacting with it.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

See [LICENSE](LICENSE).
