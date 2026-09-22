# Reporting a security issue

The Collector runs inside customer networks, so we would much rather hear about
a problem privately than read about it publicly.

**Please do not open a public issue for a security report.**

Email **security@risklence.com** with what you found, how to reproduce it, and
how you would like to be credited. We will acknowledge within two working days.

## What is in scope

- The agent in this repository, and the published image at
  `ghcr.io/risklence/risklence-scanner`.
- The signed-command protocol: anything that would let a Collector be made to
  scan a target its organisation never approved, or let a command be replayed,
  forged, or executed after expiry.
- Anything that would let the agent be made to send data it should not, or to
  act outside the boundary described in the README.

## What is out of scope

- Findings that require already having the machine's activation credential —
  that credential authenticates the Collector, so holding it is equivalent to
  being it.
- Vulnerabilities in `nmap`, `subfinder` or `nuclei` themselves. Please report
  those upstream; tell us too, so we can move the pinned versions.
- Reports that a scan detected something on a network you asked it to scan.

## Verifying what you are running

Published images are signed with cosign and ship an SBOM and a component
manifest recording the bundled tool and check-pack versions, read from the
built image rather than from source. See the README for the verification
command.
