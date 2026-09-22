# From nothing to a first scan

`README.md` documents what the Collector *is* and every command it accepts. This
covers the other half: **the path from a fresh organisation to a Collector that
has actually scanned something**, and what to do at each point where it stops.

It exists because that path has seven gates. Each one is deliberate — a Collector
runs inside a customer's network, and every gate is somebody accepting
responsibility for something. But they are only obvious once you have been
through them, and a gate you cannot see is indistinguishable from a broken
product.

Written 2026-08-25 from a real run against a live dev stack, not from reading the
code. Every command below was executed; every trap listed was hit.

---

## The ladder

Readiness is a sequence, and the platform reports exactly where you are. Ask it
at any point:

```
GET /api/v1/evidence-sources/{sourceId}/scanner/readiness
```

```json
{ "ready": false,
  "state": "discovery_boundary_approval_required",
  "blocking_reasons": ["discovery_boundary_not_approved"] }
```

`state` is the current rung. `blocking_reasons` is every reason, not just the
first — fixing one and finding another waiting is being told half the truth.

| # | State | Cleared | Where |
|---|---|---|---|
| 1 | `activation_required` | Install and activate the Collector | On the machine |
| 2 | `domain_or_network_scope_required` | Add a network range or domain, then **approve** it | In the product |
| 3 | `scan_profile_required` | Choose how thoroughly it looks | In the product |
| 4 | `scope_confirmation_required` | Confirm the boundary as a whole | In the product |
| 5 | `tool_validation_required` | `validate-tools` | On the machine |
| 6 | `target_test_required` | `test-scan` | On the machine |
| 7 | `discovery_boundary_approval_required` | Propose and approve the discovery boundary | In the product |
| ✅ | `scanner_ready` | — | — |

**Two kinds of gate, and the distinction matters.** Rungs 1, 5 and 6 are cleared
by running something on the machine the Collector lives on. The rest are
decisions taken in Risklence by a person with the authority to take them. The
product shows the exact command for the first kind and never for the second —
offering a shell command for "approve this boundary" would send somebody
entirely the wrong way.

---

## 1 · Install and activate

Add a Collector at **Configuration → Scanners → Add**, then run the command the
product gives you. It differs by installation method, because a Docker install
has no `risklence-scanner` on the operator's PATH:

```bash
# Docker
docker pull ghcr.io/risklence/risklence-scanner:latest
docker run --rm -v risklence-scanner-data:/root/.risklence-scanner \
  ghcr.io/risklence/risklence-scanner:latest \
  activate --base-url https://api.risklence.com --token <TOKEN>

# Command line
risklence-scanner activate --base-url https://api.risklence.com --token <TOKEN>
```

> **The named volume is not optional.** The Collector stores its credential in
> `~/.risklence-scanner`. A `--rm` container without that volume activates and
> forgets on exit, so every subsequent command asks for a token again.

The token is shown **once**. If you lose it, regenerate it from the Collector's
page — that rotates the credential, so the previous one stops working
immediately.

### Rotating a credential on a Collector that is already installed

You do **not** reinstall. Run `activate` with the new token against the same
data volume, and the running Collector picks it up on its next cycle:

```bash
docker run --rm -v risklence-scanner-data:/root/.risklence-scanner \
  ghcr.io/risklence/risklence-scanner:latest \
  activate --base-url https://api.risklence.com --token <NEW TOKEN>
```

The long-running container is not stopped, removed or recreated. Its log shows
the handover:

```
Heartbeat failed (401): Invalid or revoked scanner credential
Credential changed on disk — reconnecting with the new one.
Heartbeat OK — status: online.
```

> **A rotated credential is dead the moment it is rotated.** The platform
> answers `401` to the old one — there is no grace period, and no way to keep
> using it. Until you run `activate`, that Collector cannot heartbeat, poll or
> execute anything, so rotate when you intend to finish the job.

---

## 2 · Say what it may reach

On the Collector's page, **Edit**, then:

- **Approved network ranges** — add a CIDR, then **Approve** it.
- **Approved domains** — the same, for external discovery.

> **Adding is not approving.** A range sits in `draft` until somebody approves
> it, and a draft range is scanned no more than one that was never added. This
> is deliberate: "this range exists" and "we are content for it to be scanned"
> are different statements by different people.

## 3 · Say how thoroughly to look

**Scan profile**, on the same screen:

| Profile | What it does |
|---|---|
| Safe discovery | Finds what is there. Does not probe what it finds. |
| Standard discovery | Finds what is there and identifies it. |
| Extended discovery | Identifies more thoroughly, and takes longer. |
| Vulnerability assessment | Also checks what it finds for known weaknesses. |

## 4 · Confirm the boundary

**Ready to scan → Confirm this boundary.**

Approving a range says *"this range is ours"*. Confirming says *"this is the
entire set, and I am content for the Collector to work within it"* — the point
where a person becomes answerable for what will actually be reached.

---

## 5 · Prove the Collector works

```bash
docker run --rm -v risklence-scanner-data:/root/.risklence-scanner \
  ghcr.io/risklence/risklence-scanner:latest validate-tools
```

```
[OK] nmap: Nmap version 7.95
[OK] subfinder: v2.14.0
[OK] nuclei: v3.11.0
[OK] nuclei_templates: v10.4.7
[OK] raw_packet_access
```

The first four must pass. The Collector reports this itself — the platform
never inspects the machine.

> **`raw_packet_access` is reported, not required.** It is a privilege the
> container was granted (`--cap-add=NET_RAW`), not something you install, and a
> Collector without it is still ready and still scans. What it loses is the
> local segment: no MAC address and no hardware vendor, which is the only
> evidence that can name a device with nothing listening. It also loses the
> ability to distinguish *"no device at this address"* from *"we were never
> able to look"* — so grant it if you can, and Risklence will read the silence
> correctly either way.

> **The template pack ships with the image.** It is cloned from
> `github.com/projectdiscovery/nuclei-templates` at a pinned version, baked in at
> build time, and never fetched at runtime — so what runs is a reviewed,
> versioned pack rather than whatever upstream happens to hold today. If
> `nuclei_templates` reports `MISSING`, the **image** is wrong, not your machine.
> Nothing you can run will fix it; the image needs rebuilding.

> ⚠️ **The published image is currently out of date (2026-08-25, #299).** The tag
> on GHCR was built on 2026-07-19 and ships a truncated agent package — no
> `command_signing`, so it rejects every signed command and cannot run discovery
> at all, and no `nuclei_runner`/`subfinder_runner`, so it carries two binaries
> it cannot drive. Building `apps/scanner/Dockerfile` locally produces a correct
> image. Until the publish workflow is dispatched, use a local build.

## 6 · Prove it can reach something

```bash
docker run --rm --cap-add=NET_RAW --network host \
  -v risklence-scanner-data:/root/.risklence-scanner \
  ghcr.io/risklence/risklence-scanner:latest test-scan
```

A supervised scan of `127.0.0.1`. It proves the Collector can execute a scan and
report the result before it is turned loose on an estate.

---

## 7 · Approve the discovery boundary, and run

The discovery panel on the Collector's page proposes a boundary from the scope
you confirmed. Approve it, and **Start discovery** appears.

The boundary is a separate approval from step 4 on purpose: confirming scope says
what the Collector *may* reach; approving the boundary says what **this run**
will reach. A run is refused without it.

---

## Traps

Each of these cost real time on a live stack.

**A Docker Collector cannot reach the host's `127.0.0.1`.** That address *is* the
container. In development, point it at `host.docker.internal`; the platform
carries a separate `SCANNER_DOCKER_API_BASE_URL` for exactly this.

**`SCANNER_API_BASE_URL` defaults to production.** Unset, a locally created
Collector is told to connect to `api.risklence.com`. Set it per environment.

**Regenerating a token for a Collector that was never installed gives you an
install, not a reconnect.** The product now shows the fetch command first when it
has never reported in — there is nothing to reconnect.

**`poetry run` uses whichever virtualenv is active.** With the server's venv
activated, `poetry run risklence-scanner` resolves to that environment and fails
on a missing `click`. Use `env -u VIRTUAL_ENV poetry run …` from `apps/scanner`,
or the venv's binary directly.

**Empty Collector-reported fields mean it has never checked in.** Version and
OS/architecture are reported on heartbeat, not configured. Blank means no
heartbeat has arrived — which is itself the thing to act on.

---

## Diagnosing a stuck Collector

Ask the platform first — it knows which rung you are on:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://api.risklence.com/api/v1/evidence-sources/$SOURCE/scanner/readiness
```

Then ask the Collector what it thinks:

```bash
docker run --rm -v risklence-scanner-data:/root/.risklence-scanner \
  ghcr.io/risklence/risklence-scanner:latest validate-tools
```

If the two disagree, the Collector has not reported since something changed. Its
`last_heartbeat_at` on the Collector page tells you when it last spoke.

See also: `README.md` for every command, and `SECURITY.md` for what is in scope
for a security report.
