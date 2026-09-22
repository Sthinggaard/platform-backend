"""HTTP client for the Risklence Scanner agent endpoints.

Talks to ``apps/server/src/api/routes/scanner_agent.py`` using the
per-instance activation token as a Bearer credential — never a user JWT.
Those routes are the only surface this agent is allowed to call.
"""

from __future__ import annotations

import time

import requests

HEARTBEAT_PATH = "/api/v1/scanner-agent/heartbeat"
TOOLS_VALIDATE_PATH = "/api/v1/scanner-agent/tools/validate"
READINESS_PATH = "/api/v1/scanner-agent/readiness"
TEST_SCAN_PATH = "/api/v1/scanner-agent/test-scan"
NEXT_COMMAND_PATH = "/api/v1/scanner-agent/commands/next"

#: Attempts for the calls that carry a *finished scan* back to the platform.
#:
#: Søren's Collector ran a real scan and then lost it to a single 15-second
#: connect timeout: the report was one attempt, so the evidence was discarded
#: and the whole scan had to be redone from scratch. Cheap for an nmap sweep,
#: expensive for a nuclei run over 13,500 templates — and it repeats on every
#: reissue for as long as the platform is unreachable.
#:
#: Retrying is safe because the platform is idempotent here:
#: ``record_provider_execution_result`` returns the already-recorded outcome
#: when the job is in a terminal status rather than erroring or applying twice,
#: so a duplicate caused by a response lost in transit cannot corrupt anything.
#:
#: Bounded on purpose. A command carries its own ``expires_at``; retrying past
#: that just delays the agent from picking up work it can still do.
_REPORT_ATTEMPTS = 4
_REPORT_BACKOFF_SECONDS = (2.0, 5.0, 10.0)


class ScannerApiError(RuntimeError):
    """Raised when the Risklence API rejects a scanner-agent request."""


class ScannerApiClient:
    def __init__(self, base_url: str, token: str, *, timeout: float = 15.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout

    def heartbeat(
        self,
        *,
        os_name: str | None = None,
        os_version: str | None = None,
        architecture: str | None = None,
        kernel_release: str | None = None,
        container_runtime: str | None = None,
        runtime_os_name: str | None = None,
        runtime_os_version: str | None = None,
        network_segments: list[dict] | None = None,
    ) -> dict:
        body: dict = {}
        if architecture:
            body["architecture"] = architecture

        if kernel_release:
            # CA-02.3 slice 3 — os_name is sent *explicitly, including null*
            # once this agent knows the host/container distinction. Omitting it
            # would leave a stale value behind: an instance that previously
            # reported the container image's OS would keep it forever, because
            # the platform cannot tell an omitted field from a deliberate
            # "cannot be determined from in here" (#171).
            body["kernel_release"] = kernel_release
            body["os_name"] = os_name
            body["os_version"] = os_version
            body["container_runtime"] = container_runtime
            body["runtime_os_name"] = runtime_os_name
            body["runtime_os_version"] = runtime_os_version
        else:
            if os_name:
                body["os_name"] = os_name
            if os_version:
                body["os_version"] = os_version
        if network_segments is not None:
            # Sent even when empty: an empty list is the Collector saying it
            # could not find a segment, which is a different answer from an
            # older build that never reports the field at all.
            body["network_segments"] = network_segments
        return self._post(HEARTBEAT_PATH, json=body)

    def validate_tools(self, tool_status: dict[str, str], *, scanner_version: str | None = None) -> dict:
        body: dict = {"tool_status": tool_status}
        if scanner_version:
            body["scanner_version"] = scanner_version
        return self._post(TOOLS_VALIDATE_PATH, json=body)

    def report_readiness(self, payload: dict) -> dict:
        """CA-02.3 — the Collector's self-check in its own right.

        ``validate_tools`` above posts the legacy tool-status shape and is kept
        for exactly one reason: a Collector running an older binary must keep
        producing verified readiness rather than reading "unknown" until it is
        upgraded. This is the real contract — it carries *why* the check ran,
        and it is where storage and connectivity health will arrive.
        """
        return self._post(READINESS_PATH, json=payload)

    def report_test_scan(self, *, status: str, connection_verified: bool) -> dict:
        return self._post(
            TEST_SCAN_PATH,
            json={"status": status, "connection_verified": connection_verified},
        )

    def fetch_next_command(self) -> dict | None:
        """The next pending discovery command for this scanner instance, or
        None if there isn't one. Does not execute anything — see
        acknowledge_command and the CLI's ``poll`` command."""
        _kind, work = self.fetch_next_work()
        return work if _kind == "command" else None

    def fetch_next_work(self) -> tuple[str | None, dict | None]:
        """Whatever this Collector should do next, and which kind it is.

        One poll, two kinds of work. CA-08.2 added deep-verification
        inspections, and the criterion was explicit that transport reuses the
        existing channel rather than opening a second one — so this is the same
        GET, and the platform decides what to hand back.

        ``fetch_next_command`` stays as it was and still returns only discovery
        commands, so nothing that already calls it changes behaviour.
        """
        result = self._get(NEXT_COMMAND_PATH)
        if not result.get("has_command"):
            return None, None
        if result.get("inspection") is not None:
            return "inspection", result["inspection"]
        return "command", result.get("command")

    def report_inspection(
        self,
        command_id: str,
        *,
        exit_code: int | None = None,
        stderr: str = "",
        stdout: str = "",
        credential_findings: list[dict] | None = None,
        timed_out: bool = False,
        rejection_reason: str | None = None,
    ) -> dict:
        """Send back what was observed — never what it meant.

        There is no outcome argument on purpose. The Collector collects and the
        engine reads (Søren, 2026-08-24); a verdict sent from here would put the
        conclusion back on this side of the wire.
        """
        return self._post(
            f"/api/v1/scanner-agent/inspections/{command_id}/report",
            json={
                "exit_code": exit_code,
                "stderr": stderr,
                # What was read on the host, already redacted where redaction
                # applies. The platform decides what it means and never stores
                # it — see the route's own docstring.
                "stdout": stdout,
                # #296 — the shape of any credential found, never the value.
                "credential_findings": list(credential_findings or []),
                "timed_out": timed_out,
                "rejection_reason": rejection_reason,
            },
        )

    def acknowledge_command(
        self,
        command_id: str,
        *,
        accepted: bool,
        rejection_code: str | None = None,
        rejection_message: str | None = None,
        scanner_runtime_version: str | None = None,
    ) -> dict:
        body: dict = {"accepted": accepted}
        if rejection_code:
            body["rejection_code"] = rejection_code
        if rejection_message:
            body["rejection_message"] = rejection_message
        if scanner_runtime_version:
            body["scanner_runtime_version"] = scanner_runtime_version
        return self._post(f"/api/v1/scanner-agent/commands/{command_id}/acknowledge", json=body)

    def report_discovery_run_status(
        self, discovery_run_id: str, *, status: str | None = None, stage: str | None = None
    ) -> dict:
        """CA-04.1 — the whole-run result report a real, executed command
        sends back (discovery_command_agent.py's existing status route, not
        discovery_execution_agent.py's per-job result route, which requires
        a provider_execution_id this whole-run command never has)."""
        body: dict = {}
        if status is not None:
            body["status"] = status
        if stage is not None:
            body["stage"] = stage
        # Retried: this is where a completed whole-run scan is handed over.
        return self._post(
            f"/api/v1/scanner-agent/discovery-runs/{discovery_run_id}/status",
            json=body,
            attempts=_REPORT_ATTEMPTS,
        )

    def report_provider_execution_result(
        self,
        command_id: str,
        *,
        status: str,
        evidence_format: str | None = None,
        raw_evidence_payload: str | None = None,
        failure_code: str | None = None,
        failure_message: str | None = None,
    ) -> dict:
        """CA-04.3 — the per-job result report a delegated command (one
        tied to a ProviderExecution — Subfinder today, Nmap-via-delegation
        in the future) sends back (discovery_execution_agent.py's result
        route), not the whole-run status route CA-04.1 built for the
        original Step 4.1 command path."""
        body: dict = {"status": status}
        if evidence_format is not None:
            body["evidence_format"] = evidence_format
        if raw_evidence_payload is not None:
            body["raw_evidence_payload"] = raw_evidence_payload
        if failure_code is not None:
            body["failure_code"] = failure_code
        if failure_message is not None:
            body["failure_message"] = failure_message
        # Retried: this call carries the evidence payload itself, so losing it
        # to one blip means re-running the scan that produced it.
        return self._post(
            f"/api/v1/scanner-agent/commands/{command_id}/result",
            json=body,
            attempts=_REPORT_ATTEMPTS,
        )

    def _get(self, path: str) -> dict:
        try:
            response = requests.get(
                f"{self._base_url}{path}",
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise ScannerApiError(f"Could not reach Risklence at {self._base_url}{path}: {exc}") from exc
        if response.status_code >= 400:
            raise ScannerApiError(f"{path} failed ({response.status_code}): {response.text}")
        return response.json()

    def _post(self, path: str, json: dict | None = None, *, attempts: int = 1) -> dict:
        """POST, optionally retrying a call that carries already-completed work.

        ``attempts`` > 1 is reserved for the result reports — see
        ``_REPORT_ATTEMPTS``. Everything else stays single-attempt: a failed
        heartbeat or poll costs nothing to repeat on the next cycle, so
        retrying inside the call would only delay the loop.

        **Only transport failures are retried**, never an HTTP error status. A
        4xx is the platform's considered answer — an expired command, a revoked
        credential — and repeating it would turn a clear rejection into a slow
        one.
        """
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                response = requests.post(
                    f"{self._base_url}{path}",
                    json=json or {},
                    headers={"Authorization": f"Bearer {self._token}"},
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt + 1 < attempts:
                    time.sleep(_REPORT_BACKOFF_SECONDS[min(attempt, len(_REPORT_BACKOFF_SECONDS) - 1)])
                    continue
                raise ScannerApiError(
                    f"Could not reach Risklence at {self._base_url}{path} "
                    f"after {attempts} attempt(s): {exc}"
                ) from exc
            if response.status_code >= 400:
                raise ScannerApiError(f"{path} failed ({response.status_code}): {response.text}")
            return response.json()
        # Unreachable: the loop either returns or raises.
        raise ScannerApiError(f"Could not reach Risklence at {self._base_url}{path}: {last_exc}")
