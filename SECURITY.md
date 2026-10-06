# Security Policy

## Supported versions

Security fixes are provided for the latest released version and the current development branch.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the project maintainer rather than opening a public issue with exploit details. Include the affected version, reproduction steps, impact, and any proof of concept that can be shared safely.

Do not include secrets, credentials, or personal data in the report.

## Security expectations

- The application accepts only HTTPS URLs.
- URL validation is performed before network access.
- Private, loopback, link-local, reserved, and DNS-resolved internal addresses are rejected.
- Redirects are disabled and HTTP responses are size-limited.
- No submitted URL is uploaded to a remote service.
- The application does not execute shell commands built from user input.

## Disclosure

The maintainer will acknowledge the report, investigate and remediate the issue, and coordinate a public disclosure after a suitable fix is available.
