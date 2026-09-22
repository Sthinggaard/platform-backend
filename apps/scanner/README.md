# Risklence Collector

The Risklence Collector is a small agent you run **inside your own network**. It
discovers what infrastructure you actually have, and reports that evidence back
to Risklence.

It is deliberately open. This is software you install inside your perimeter, so
you should be able to read exactly what it does before you trust it — what it
scans, what it sends, and what it never touches.

```bash
docker pull ghcr.io/risklence/risklence-scanner:latest
```

**Setting one up for the first time?** [`FIRST-SCAN.md`](FIRST-SCAN.md) walks the
whole path from a fresh organisation to a Collector that has actually scanned
something — the seven readiness gates, which are cleared on the machine and which
are decisions taken in Risklence, and the traps each one hides.

---

## What it does, and does not do

**It does:**

- Discover hosts and open services on networks **you have explicitly approved**
  in Risklence.
- Enumerate subdomains of domains **you have explicitly approved**.
- Optionally run vulnerability checks from a **pinned, bundled** check pack.
- Report its own health — which components work, whether it can store evidence,
  how stable its connection is.

**It does not:**

- Scan anything outside the boundary you approved. Every job it receives is
  cryptographically signed and names its own targets; a command that fails
  verification is rejected, not executed.
- Download checks from the internet at run time. The check pack is pinned into
  the image at build time, so what runs is exactly what was published.
- Send file contents, credentials, or user data. It reports hosts, ports,
  service banners and its own status.
- Make changes. It never remediates, reconfigures, or writes to anything it
  scans.

---

## Install

### Docker (recommended)

```bash
docker pull ghcr.io/risklence/risklence-scanner:latest
```

Activate it once with the token shown on the Risklence setup screen:

```bash
docker run --rm \
  -v risklence-scanner-data:/root/.risklence-scanner \
  ghcr.io/risklence/risklence-scanner:latest \
  activate --base-url https://api.risklence.com --token <YOUR_TOKEN>
```

Then leave it running:

```bash
docker run -d --name risklence-scanner --restart unless-stopped \
  --cap-add=NET_RAW --network host \
  -v risklence-scanner-data:/root/.risklence-scanner \
  ghcr.io/risklence/risklence-scanner:latest \
  run --interval 60
```

> **Why `--cap-add=NET_RAW`.** Without it the Collector cannot ARP the local
> segment, so it never sees a MAC address or a hardware vendor. That matters
> twice over: a hardware vendor is the only thing that can name a device with
> nothing listening — *"Ubiquiti device"* rather than a bare `192.168.1.1` —
> and a MAC is what tells a real device apart from an address that merely
> answered. Without it, "nothing is here" and "we could not look" arrive as the
> same observation.
>
> The Collector runs **without** it if you would rather not grant it. It scans
> exactly as before and simply learns less, and it reports the capability as
> unavailable so Risklence knows to read its silence as *"could not look"*
> rather than *"nothing there"*.

> **Network visibility matters.** By default a container sees the Docker
> network, not your LAN, and results will be wrong rather than merely
> incomplete. On Linux, use `--network host` so the Collector discovers what the
> machine itself can see. On Docker Desktop (macOS/Windows) there is no true
> host networking — the container sits behind a virtual network stack that can
> answer for addresses which do not exist, so **do not trust discovery results
> from Docker Desktop.** Run the Collector on the Linux host you actually want
> to scan from.

### From source

Requires Python 3.11+, [Poetry](https://python-poetry.org/), and `nmap`,
`subfinder` and `nuclei` on `PATH`.

```bash
poetry install
poetry run risklence-scanner --help
```

Installing from source does **not** give you the vulnerability check pack — it
is bundled into the Docker image at build time and is not downloaded at run
time by design. Scan profiles that include vulnerability checks will report the
pack as missing until you install it at `~/nuclei-templates`.

---

## Commands

Run `risklence-scanner --help`, or `--help` on any command, for the current
surface.

### `activate`

Binds this machine to a Collector in your Risklence organisation and stores the
credential locally.

```bash
risklence-scanner activate --base-url https://api.risklence.com --token <TOKEN>
```

| Option | Description |
| --- | --- |
| `--base-url` | Your Risklence API base URL. Required. |
| `--token` | The activation token from the setup screen. Required, shown once. |

The credential is written to `~/.risklence-scanner/credentials.json`
(override the directory with `RISKLENCE_SCANNER_HOME`). Keep it as you would any
credential: it authenticates this machine as your Collector.

### `run`

The one you want for normal operation. Runs as a persistent process:
heartbeats, polls for approved work, executes it, reports results, and
periodically checks its own health.

```bash
risklence-scanner run --interval 60
```

| Option | Default | Description |
| --- | --- | --- |
| `--interval` | `60` | Seconds between heartbeat/poll cycles. Must stay **well below** the
platform's worker lease (300s): a command's lease starts when the platform issues it, so a
Collector that polls only once per lease window can lose the job before it has claimed it.
This was `300` — exactly the lease — and every long run retried (#322). |

A shorter interval means Risklence notices problems sooner and work starts
sooner; it does not make scans faster. `SIGTERM` and `SIGINT` both stop it
cleanly after the current cycle rather than killing work in flight.

Transient network failures are expected and survived: a failed heartbeat or
poll is retried on the next cycle, and a completed scan whose result cannot be
delivered is retried rather than discarded.

### `heartbeat`

Sends a single liveness ping and reports this machine's identity (kernel,
architecture, and — when not containerised — its operating system).

### `validate-tools`

Checks the bundled tools locally and reports the result to Risklence.

```bash
risklence-scanner validate-tools
```

Prints each component and whether it works. This is the same self-check the
`run` loop performs on its own, so you rarely need to invoke it by hand; it is
useful when diagnosing a Collector that reports a component as missing.

### `poll`

Fetches the next pending job, verifies its signature, executes it if it
verifies, and reports the result. One-shot equivalent of a single `run` cycle,
intended for scripted or manual use.

### `test-scan`

Runs a small, safe scan against one approved target and records the outcome —
used during setup to prove the Collector can genuinely reach and scan something.

```bash
risklence-scanner test-scan --target 127.0.0.1
```

### `install` / `uninstall`

Installs the agent as a **user-level** systemd service (Linux, non-Docker
installs). No root and no `sudo`: the unit is written to
`~/.config/systemd/user/` and runs as you.

```bash
risklence-scanner install
risklence-scanner uninstall
```

Docker installs do not need these — a container's own restart policy already
does the job.

---

## How it decides what to scan

The Collector has no standing permission to scan anything. Every job arrives as
a signed command that names its own approved targets and carries an expiry. The
agent verifies the signature, the expiry, and that the command was issued to
*this* Collector before doing anything; a command failing any of those is
rejected with a reason, never executed.

This means approving a boundary in Risklence is what grants scanning authority,
and revoking it takes that authority away — the Collector cannot widen its own
scope.

---

## Diagnosing a Collector

```bash
# Is it running and reaching Risklence?
docker logs -f risklence-scanner

# What does it think it can do?
docker exec risklence-scanner risklence-scanner validate-tools
```

**"cannot do the approved vulnerability check pack"** — the Collector has the
`nuclei` binary but not its check pack. Nuclei without checks is an engine with
nothing to run. Either use the Docker image, which bundles a pinned pack, or
choose a scan profile that does not include vulnerability checks.

**Discovery finds implausibly many hosts** — almost always Docker Desktop. See
the network note under Install.

**Nothing happens after activation** — the Collector polls rather than being
pushed to, so work begins on the next cycle (up to `--interval` seconds).

---

## Updating and rolling back

```bash
docker pull ghcr.io/risklence/risklence-scanner:latest
docker rm -f risklence-scanner
# then re-run the `run` command above
```

Your credential lives in the `risklence-scanner-data` volume, so it survives
replacing the container — you do not re-activate. To pin or roll back, use an
immutable tag rather than `latest`:

```bash
docker pull ghcr.io/risklence/risklence-scanner:sha-abc1234
```

---

## Verifying what you are running

Published images are signed with [cosign](https://docs.sigstore.dev/) using
keyless signing, so the signature is bound to the workflow that built it:

```bash
cosign verify ghcr.io/risklence/risklence-scanner:latest \
  --certificate-identity-regexp 'https://github.com/Risklence/scanner/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each release also publishes an SBOM and a component manifest recording the
bundled tool and check-pack versions, read from the built image itself rather
than from source, so it cannot drift from what actually shipped.

---

## Tests

```bash
poetry install
poetry run pytest
```

---

## Reporting a problem

Security issues: please report privately to security@risklence.com rather than
opening a public issue.

Everything else: open an issue on this repository. Note that the Collector's
source is developed alongside the Risklence platform, so fixes are applied
there and mirrored here on release — a pull request may be applied rather than
merged directly, and you will be credited either way.
