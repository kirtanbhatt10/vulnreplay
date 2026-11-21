# Ecosystem comparison and VulnReplay's contribution

This document records the research done before building VulnReplay: what established tools already do well,
where the gaps are, and what VulnReplay deliberately does *not* try to replace.

## Tools studied

| Tool | Primary job | Strengths | Gaps relative to incident regression |
| --- | --- | --- | --- |
| **OWASP ZAP** | DAST scanner and intercepting proxy | Free and open source, mature passive and active rules, Automation Framework (one YAML plan) for CI, GitHub Actions | Finds *classes* of issues; it doesn't turn one specific confirmed finding into a permanent, assertion-rich test. Authorization flaws between two users need custom scripting. |
| **Burp Suite** | Manual testing proxy, scanner (Pro/Enterprise) | Best-in-class manual workflow (Repeater, Intruder), rich extensions, exportable request/response items | Repeater history isn't a regression suite. Verifying a fix means manually re-sending. CI use needs the commercial edition. |
| **Nuclei** | Template-based scanner | Huge community template library, fast, YAML templates, authenticated scanning and fuzzing in v3 | Templates are written by hand, per vulnerability class. There's no evidence import, no baseline/after comparison and no notion of "this was fixed and must stay fixed". |
| **Playwright** | Browser and API test automation | Reliable browser automation, `APIRequestContext` for HTTP tests, excellent CI story | General-purpose. You have to write the security test yourself, and it has no evidence provenance or safety controls. |
| **Schemathesis** | Property-based API fuzzing from OpenAPI/GraphQL | Finds crashes and schema violations automatically, pytest integration, stateful testing via links | Needs a spec. Results are non-deterministic by design. It doesn't reproduce a specific historic incident or check object-level authorization between users. |
| **RESTler** | Stateful REST API fuzzing | Infers producer/consumer dependencies, finds state bugs | Same as above: a fuzzer, not a regression oracle for a confirmed finding. Heavier setup. |
| **Dredd** | Contract testing against API Blueprint/OpenAPI | Simple, deterministic "does the implementation match the docs" | Tests conformance, not security properties. Considered legacy by several 2026 practitioner guides. |
| **API regression frameworks** (pytest+HTTPX, REST Assured, Karate, Postman/Newman) | Hand-written functional tests | Flexible and familiar to developers | Security fixes rarely get tests. When they do, the test usually only asserts a status code. No evidence linkage or SSRF-safe execution. |
| **Incident reproduction** (ad-hoc scripts, replaying HAR/Burp items) | One-off reproduction | Quick | Scripts embed captured tokens, hit arbitrary hosts, and are thrown away after the ticket closes. |

## The gap

No tool in this set takes **the evidence of a specific confirmed vulnerability** and turns it into a
**safe, deterministic test** with an **explicit secure expectation** that is **run before and after the fix**,
with the **comparison as proof**, and is then **kept as a permanent CI regression gate**.

## What VulnReplay contributes

1. **Evidence-to-test pipeline across formats.** Burp, ZAP, HAR, SARIF, raw HTTP, JSON and JSONL logs all
   normalize into one exchange model with SHA-256 fingerprints and provenance. Original bytes are preserved.
2. **Category-aware secure expectations derived from the original response.** For IDOR/BOLA the generator pulls
   the sensitive values the original response leaked (emails, card digits, owner fields). The test asserts
   those values are absent, not merely that the status became 403.
3. **Multi-user authorization replay** (owner vs attacker) with value extraction between steps. A value the
   owner legitimately read in the control request must not reach the attacker.
4. **A regression classifier that refuses status-only proof.** Every run is classified as *reproduced*,
   *verified*, *regression*, *inconclusive* or *failed*. A partial fix (correct 403, data still in the body)
   is reported as an *incomplete remediation*, and a status-only change is *inconclusive*.
5. **Safety by construction.** Tests are data, not code. There is a closed assertion set, relative paths only,
   and destructive payloads are rejected. Execution needs an operator host allowlist *and* admin
   authorization, has per-request DNS re-validation with IP pinning, same-target-only redirects, request
   budgets, throttling and redaction.
6. **Portable outputs.** The same definition renders to pytest/HTTPX and Playwright, runs in CI through a CLI
   and GitHub Action with baselines and SARIF, and produces HTML/PDF/JSON reports with integrity hashes.

## How it fits alongside existing tools

VulnReplay is **downstream** of scanners and manual testing. Use ZAP, Burp or Nuclei to *find* issues and
Schemathesis or RESTler to *fuzz*. Use VulnReplay to *prove the fix* and *keep it fixed*. The importers exist
exactly so that output from those tools becomes VulnReplay input.

## Sources consulted (November 2026)

* OWASP ZAP Automation Framework documentation and blog (zaproxy.org)
* ProjectDiscovery Nuclei release notes and v3 announcements (github.com/projectdiscovery/nuclei)
* Schemathesis project and 2026 comparison articles (Schemathesis vs Dredd, API fuzzing best practices)
* "REST API Testing in DevOps" (arXiv 2410.12547) and "Automated Test Generation for REST APIs: No Time to Rest
  Yet" (arXiv 2204.08348), both comparing RESTler, Schemathesis, EvoMaster and others
* TestGuild "Best API Testing Tools in 2026", which lists Dredd as legacy
