# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Haven, please report it responsibly.

**Do not open a public issue.** Instead, use one of the following:

- **GitHub Security Advisories**: [Report a vulnerability](https://github.com/markjsapp/Haven/security/advisories/new) (preferred)
- **Email**: Send details to the maintainer listed in the repository

## What to include

- Description of the vulnerability
- Steps to reproduce
- Affected versions or commits
- Suggested fix (if any)

## Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: As soon as practical, depending on severity

## Scope

This policy covers the Haven server (`src/`), the haven-core library (`packages/haven-core/`), and the web frontend (`packages/web/`). It does not cover third-party dependencies, though we will coordinate upstream reports when applicable.

## Cryptographic concerns

Haven's E2EE implementation (X3DH, Double Ratchet, Sender Keys) is a critical component. If you identify weaknesses in the cryptographic protocol, key management, or side-channel vulnerabilities, these are treated as highest priority.
