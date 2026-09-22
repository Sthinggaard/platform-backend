"""Set up one real deep-verification inspection against the dev stack.

CA-08 has no UI yet, so there is no way to queue an inspection by hand. This
builds the whole chain the platform would build for itself — Connector,
approved permission profile, access lifecycle, verification run, queued
inspection — and prints what the Collector needs to fetch it.

**This is dev-stack scaffolding, not a fixture pretending to be an observation.**
Everything it creates is written by this script; nothing here was discovered by
scanning anything. Run it against the local dev database only.

**Re-runnable, because it has to be.** A signed inspection is valid for five
minutes, so queueing another one is the normal case rather than the exception.
The first version created a fresh lifecycle every time and hit
``uq_artefact_access_lifecycle_artefact`` on the second run. It now reuses the
Connector, profile, lifecycle and run it finds, and only queues a new
inspection.

Usage, from ``apps/server``::

    poetry run python scripts/seed_verification_inspection.py \\
        --host pi-local.local --username thinggaard --capability read_os_version

Then, from ``apps/scanner``::

    env -u VIRTUAL_ENV poetry run risklence-scanner add-host-credential \\
        --connector-id <printed id> --host pi-local.local \\
        --username thinggaard --identity-file ~/.ssh/id_ed25519_pi
    env -u VIRTUAL_ENV poetry run risklence-scanner poll

``env -u VIRTUAL_ENV`` is not decoration: with the server's venv active,
``poetry run`` resolves to that environment and the scanner CLI fails on a
missing ``click``.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from sqlalchemy import select

from src.core.constants.access_connector_enums import (
    AccessConnectorStatus,
    AccessConnectorType,
    ConnectorCredentialModel,
)
from src.core.constants.artefact_access_lifecycle_enums import ArtefactAccessState
from src.core.constants.permission_profile_enums import (
    ConnectorCapability,
    PermissionProfileStatus,
    PermissionSubjectKind,
)
from src.core.constants.verification_run_enums import (
    VerificationApprovalSource,
    VerificationRunStatus,
)
from src.core.database import get_session_factory
from src.core.model_defs.access_connector import AccessConnector
from src.core.model_defs.artefact_access_lifecycle import ArtefactAccessLifecycle
from src.core.model_defs.assets_runtime import Asset
from src.core.model_defs.evidence_scanner import ScannerInstance
from src.core.model_defs.permission_profile import PermissionProfile
from src.core.model_defs.verification_run import VerificationRun
from src.core.models import User
from src.core.services.permission_subject_service import register_permission_subject
from src.core.services.verification_inspection_queue_service import queue_inspection


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="Host the Collector will SSH into.")
    parser.add_argument("--username", required=True, help="Account on that host.")
    parser.add_argument(
        "--capability",
        default=ConnectorCapability.READ_OS_VERSION.value,
        help="Which read to queue. read_os_version needs no platform.",
    )
    parser.add_argument(
        "--platform",
        default=None,
        help="debian/rhel/alpine — only needed for read_installed_packages.",
    )
    args = parser.parse_args()

    db = get_session_factory()()
    try:
        # Ordered, because an unordered LIMIT 1 lets Postgres return a
        # different instance on each run — which printed the wrong Collector id
        # while queueing the work correctly for another, and would send the next
        # person to look at a Collector that was never given anything.
        instance = db.execute(
            select(ScannerInstance)
            .where(ScannerInstance.command_signing_key_encrypted.is_not(None))
            .order_by(ScannerInstance.id)
            .limit(1)
        ).scalars().first()
        if instance is None:
            print(
                "No scanner instance has a per-instance signing key. Activate a Collector "
                "first — an inspection cannot be signed without one, and this script will "
                "not fall back to the legacy shared secret.",
                file=sys.stderr,
            )
            return 1

        org_id = instance.organization_id
        # From here on, `instance` is only used to establish the organisation and
        # to seed a *new* connector. An existing connector keeps its own.
        user = db.execute(
            select(User).where(User.organization_id == org_id).limit(1)
        ).scalars().first()
        if user is None:
            print(f"No user in organisation {org_id}.", file=sys.stderr)
            return 1

        asset = db.execute(
            select(Asset).where(Asset.organization_id == org_id).limit(1)
        ).scalars().first()
        if asset is None:
            print(f"No asset in organisation {org_id} to verify.", file=sys.stderr)
            return 1

        now = datetime.now(timezone.utc)

        # Everything below is reused when it already exists. Re-running must
        # queue a second inspection, not fail on a constraint.
        connector = db.execute(
            select(AccessConnector).where(
                AccessConnector.organization_id == org_id,
                AccessConnector.target_host == args.host,
            ).limit(1)
        ).scalars().first()
        if connector is None:
            subject = register_permission_subject(
                db, organization_id=org_id, subject_kind=PermissionSubjectKind.ACCESS_CONNECTOR
            )
            connector = AccessConnector(
                organization_id=org_id,
                permission_subject_id=subject.id,
                scanner_instance_id=instance.id,
                connector_type=AccessConnectorType.SSH_RESTRICTED.value,
                credential_model=ConnectorCredentialModel.OPERATOR_SUPPLIED.value,
                target_host=args.host,
                target_username=args.username,
                status=AccessConnectorStatus.CONFIGURED.value,
            )
            db.add(connector)
            db.flush()

        # Approved directly rather than through the lifecycle: this is
        # scaffolding for a transport test, and the approval path has its own
        # tests. Written down so nobody reads this as "approval is optional".
        profile = db.execute(
            select(PermissionProfile).where(
                PermissionProfile.subject_id == connector.permission_subject_id,
                PermissionProfile.status == PermissionProfileStatus.ACTIVE.value,
            ).limit(1)
        ).scalars().first()
        if profile is None:
            profile = PermissionProfile(
                organization_id=org_id,
                subject_id=connector.permission_subject_id,
                name="Manual verification test",
                capabilities=[args.capability],
                discovery_capabilities=[],
                status=PermissionProfileStatus.ACTIVE.value,
                version=1,
                prepared_by_user_id=user.id,
                approved_by_user_id=user.id,
                approved_at=now,
            )
            db.add(profile)
            db.flush()
        elif args.capability not in (profile.capabilities or []):
            # Widened in place *only here*, because this is scaffolding. The
            # product refuses this — a profile is superseded, never edited —
            # and permission_profile_service is where that rule lives.
            profile.capabilities = list(profile.capabilities or []) + [args.capability]
            db.add(profile)
            db.flush()

        # One lifecycle per artefact, enforced by
        # uq_artefact_access_lifecycle_artefact.
        lifecycle = db.execute(
            select(ArtefactAccessLifecycle).where(
                ArtefactAccessLifecycle.organization_id == org_id,
                ArtefactAccessLifecycle.asset_id == asset.id,
            ).limit(1)
        ).scalars().first()
        if lifecycle is None:
            lifecycle = ArtefactAccessLifecycle(
                organization_id=org_id,
                asset_id=asset.id,
                state=ArtefactAccessState.RUNNING.value,
                requested_choice="deep_verification",
                requested_at=now,
                verification_approved_at=now,
                verification_approved_by_user_id=user.id,
                verification_approved_source=VerificationApprovalSource.PER_ARTEFACT.value,
                running_at=now,
            )
            db.add(lifecycle)
            db.flush()

        run = db.execute(
            select(VerificationRun).where(
                VerificationRun.organization_id == org_id,
                VerificationRun.asset_id == asset.id,
                VerificationRun.status == VerificationRunStatus.RUNNING.value,
            ).limit(1)
        ).scalars().first()
        if run is None:
            run = VerificationRun(
                organization_id=org_id,
                asset_id=asset.id,
                lifecycle_id=lifecycle.id,
                approval_source=VerificationApprovalSource.PER_ARTEFACT.value,
                approved_by_user_id=user.id,
                approved_at=now,
                permission_profile_id=profile.id,
                status=VerificationRunStatus.RUNNING.value,
                began_by_user_id=user.id,
            )
            db.add(run)
            db.flush()

        command = queue_inspection(
            db,
            run=run,
            connector=connector,
            capability=args.capability,
            platform=args.platform,
        )
        db.commit()

        print("Queued one inspection.\n")
        print(f"  organisation      {org_id}")
        print(f"  asset             {asset.id} ({asset.display_name})")
        # The instance that will actually be handed this work is the
        # *connector's*, because queue_inspection takes it from there — not the
        # one looked up above, which only answers "which organisation are we in".
        print(f"  scanner instance  {connector.scanner_instance_id}")
        print(f"  connector id      {connector.id}")
        print(f"  capability        {command.capability}")
        print(f"  argv              {command.argv}")
        print(f"  expires at        {command.expires_at} UTC "
              f"(inspections are short-lived — poll promptly)\n")
        # `env -u VIRTUAL_ENV`, not a bare `poetry run`. With the server's own
        # venv activated — which it usually is, since that is how this script is
        # run — poetry resolves to *that* environment and the scanner CLI dies
        # on `ModuleNotFoundError: No module named 'click'`. Printing a command
        # that does not work is worse than printing none.
        print("Next, from apps/scanner:\n")
        print(
            f"  env -u VIRTUAL_ENV poetry run risklence-scanner add-host-credential \\\n"
            f"      --connector-id {connector.id} \\\n"
            f"      --host {args.host} --username {args.username} \\\n"
            f"      --identity-file ~/.ssh/id_ed25519_pi\n"
            f"  env -u VIRTUAL_ENV poetry run risklence-scanner poll\n"
        )
        print(
            "  (first time only: `cd apps/scanner && env -u VIRTUAL_ENV poetry install`)"
        )
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
