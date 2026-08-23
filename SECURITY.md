# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| v0.1.x | ✅ |

## Reporting a vulnerability

Please report privately via **GitHub Security Advisories** ("Report a vulnerability"
on the Security tab) rather than a public issue.

- You'll get an acknowledgment within **72 hours**.
- We aim to release fixes for critical issues within **30 days**.

## Scope notes

ThreatIntelHub is self-hosted single-admin software. The following are out of scope:

- Misconfiguration of your own deployment (exposed ports, weak admin password, shared host)
- Vulnerabilities in upstream services (VirusTotal, AbuseIPDB, OTX, Shodan)
- Denial-of-service against your own instance

API keys are stored Fernet-encrypted at rest and never returned in plaintext by the API.
