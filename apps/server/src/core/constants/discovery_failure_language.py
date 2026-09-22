"""UX-DISC-02 (#128) — the one place a discovery failure is put into words.

The customer-facing execution panel used to render whatever string happened to
be stored on the failed record. Three of those strings are not written for a
reader at all:

* ``failure_message=str(exc)`` — a raw Python exception, from the scheduler's
  provider-execution guard;
* ``"Worker lease expired before the job reported a result."`` — lease and queue
  mechanics, and the literal wording that put ``worker_lease_expired`` in front
  of an executive;
* ``command.rejection_message`` — free text the Collector supplied, which the
  platform never authored and cannot vouch for.

So the panel is composed from the **failure code** instead, which is a closed
vocabulary (``RETRYABLE_FAILURE_CODES``/``NON_RETRYABLE_FAILURE_CODES`` and
their provider-level counterparts), and a code with no statement here resolves
to a safe generic rather than falling back to the stored text — a fallback is
how the raw string would return the first time a new code appears.

The stored ``failure_message`` is untouched and stays on the record: it is
genuine diagnostic evidence, and belongs in the audit trail, not on the screen
a CEO watches a first discovery from.
"""

from __future__ import annotations

#: Said when the code is one this build has no statement for. It never guesses
#: at a cause, and never claims the platform knows more than it does.
DISCOVERY_FAILURE_UNKNOWN_STATEMENT = (
    "This step reported a problem that this page cannot explain in detail yet. "
    "The full record is kept in the activity trail."
)

#: Run-level: set before execution begins, by the request's own validation or
#: by the Collector rejecting the command.
RUN_FAILURE_STATEMENTS: dict[str, str] = {
    # Retryable — something is temporarily in the way.
    "scanner_offline": "The secure collector was not reachable when this discovery was requested.",
    "provider_timeout": "This discovery took longer than allowed and was stopped before it finished.",
    "command_delivery_failed": "The instruction to start could not be delivered to the secure collector.",
    "scanner_busy": "The secure collector was already working on another discovery.",
    "scanner_locally_paused": "The secure collector has been paused on the machine it runs on.",
    "upload_interrupted": "The evidence gathered was interrupted on its way back and did not arrive complete.",
    "run_not_accepting_work": "This discovery had already been stopped by the time work was reported against it.",
    "command_expired": "The instruction to start was not collected in time and is no longer valid.",
    "command_rejected": "The secure collector declined to run this discovery.",
    # Non-retryable — a decision or a configuration has to change first.
    "scope_not_approved": "One or more of the selected targets is outside the approved boundary.",
    "target_not_locally_approved": "One or more of the selected targets is not approved on the collector itself.",
    "permission_denied": "This discovery was not permitted under the access this organisation has granted.",
    "scanner_activation_revoked": "This secure collector's access has been withdrawn.",
    "profile_unsupported": "The selected scan depth is not supported by this secure collector.",
    "capability_unavailable": "The secure collector does not have the tools this scan depth requires.",
    "check_key_unknown": "This discovery asked for a check the secure collector does not recognise.",
    "invalid_organisation_binding": "This secure collector is not registered to this organisation.",
    "organisation_mismatch": "This secure collector is not registered to this organisation.",
    "scanner_instance_mismatch": "This instruction was addressed to a different secure collector.",
    "command_signature_invalid": "The instruction to start could not be verified as genuine and was refused.",
    "maintenance_approval_expired": "The approval covering this discovery had lapsed before it could start.",
    "maintenance_window_closed": "This discovery was outside the window the organisation approved.",
    # Blocked before a request is even accepted (discovery_run_service's own
    # precondition codes, which land on failure_code for a BLOCKED run).
    "technical_owner_required": "No Technical Setup Owner has been assigned yet.",
    "scanner_not_activated": "This secure collector has not been activated.",
    "discovery_profile_required": "No scan depth has been chosen for this secure collector.",
    "scanner_capability_required": "The secure collector has not confirmed it has the tools this scan depth needs.",
}

#: Provider-level: set on the individual job inside the execution plan.
PROVIDER_FAILURE_STATEMENTS: dict[str, str] = {
    # Retryable.
    "provider_timeout": "This step took longer than allowed and was stopped before it finished.",
    "worker_lease_expired": "The secure collector stopped reporting part-way through this step.",
    "worker_crashed": "The secure collector stopped unexpectedly part-way through this step.",
    "transient_network_error": "The network was unreachable part-way through this step.",
    "rate_limited": "This step was slowed down by the service it was querying and did not finish.",
    "evidence_storage_failed": "The evidence this step gathered could not be stored.",
    # Non-retryable.
    "provider_not_registered": "This step cannot run: the platform has nothing registered to perform it.",
    "provider_execution_error": "This step stopped on an unexpected error and did not finish.",
    "provider_reported_failure": "The secure collector reported that this step did not succeed.",
    "direct_provider_failure": "This step did not succeed.",
    "credentials_invalid": "The access this step needs was refused.",
    "capability_unsupported": "The secure collector cannot perform this step.",
    "target_invalid": "One of the targets for this step could not be read.",
    "checkpoint_corrupt": "This step's saved progress could not be read, so it cannot be resumed.",
    "unknown_failure": DISCOVERY_FAILURE_UNKNOWN_STATEMENT,
}


def run_failure_statement(code: str | None) -> str:
    """The sentence shown for a run-level failure. Never the stored message."""
    if not code:
        return DISCOVERY_FAILURE_UNKNOWN_STATEMENT
    return RUN_FAILURE_STATEMENTS.get(code, DISCOVERY_FAILURE_UNKNOWN_STATEMENT)


def provider_failure_statement(code: str | None) -> str:
    """The sentence shown for a failure inside the execution plan."""
    if not code:
        return DISCOVERY_FAILURE_UNKNOWN_STATEMENT
    return PROVIDER_FAILURE_STATEMENTS.get(code, DISCOVERY_FAILURE_UNKNOWN_STATEMENT)
