# Security policy

Studge Pass is pre-alpha software. Do not store real passwords in it yet.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub security
advisories:

<https://github.com/lnstudge/Studge-Pass/security/advisories/new>

Please do **not** open a public issue for a suspected vulnerability.

Include, where you can: the affected component (core, relay, cli, a client), the
version or commit, steps to reproduce, and the impact you believe it has.

## Scope

All components in this repository are in scope: the core library, the relay, the
CLI, every client, the build and CI configuration.

Of particular interest:

- anything that could expose secrets or plaintext (logs, errors, telemetry, UI);
- anything that would let the relay read, modify, reorder, roll back or
  substitute vault data without a client detecting it;
- weaknesses in authentication, key derivation or the cipher suite;
- supply-chain issues in the build, dependencies or CI.

## Disclosure

We follow coordinated disclosure. We will credit reporters in the advisory
unless they prefer to stay anonymous.
