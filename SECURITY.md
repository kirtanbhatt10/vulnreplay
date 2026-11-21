# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ |

## Reporting a vulnerability

Please **do not open a public issue** for security problems in VulnReplay itself.

Use GitHub's private vulnerability reporting (*Security → Report a vulnerability*) on
<https://github.com/kirtanbhatt10/vulnreplay>. Include affected version, impact, reproduction steps and any
proof-of-concept limited to a local installation.

You can expect an acknowledgement within 5 business days and a fix or mitigation plan within 30 days for
confirmed issues. Credit is given in the changelog unless you prefer otherwise.

## Scope notes

* `lab/demo_app` is **deliberately vulnerable**. Reports about its intended vulnerabilities are out of scope.
  Escapes from its isolation (e.g. the Compose network becoming reachable externally) are in scope.
* Use VulnReplay only against systems you own or are explicitly authorized to test.

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the security design.
