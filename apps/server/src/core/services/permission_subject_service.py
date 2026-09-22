"""CA-07.3 / Epic C4 — registering a permissionable thing, and the shape of one.

Two small pieces, and between them they are the whole of "make this polymorphic":

- `PermissionSubjectBearer` is the **code** half. Anything carrying an
  `organization_id`, a `permission_subject_id` and an answer to "are you
  still usable?" can be permissioned, so
  `assert_capability_permitted` needs no branch per subject kind and no change
  when a new one arrives. This is the flexibility a `subject_type`/`subject_id`
  column pair is usually reached for — and it costs nothing, because it lives in
  the type system rather than in the database.

- `register_permission_subject` is the **storage** half: one row in the
  supertable, which the concrete table then points at with a real foreign key.

Adding a new kind of permissionable thing is therefore: add a member to
`PermissionSubjectKind`, give the table a `permission_subject_id`, and call this
on create. Nothing in `permission_profiles`, and nothing in the enforcement path,
changes at all.

The caller owns the transaction (commit).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from sqlalchemy.orm import Session

from src.core.constants.permission_profile_enums import PermissionSubjectKind
from src.core.model_defs.permission_subject import PermissionSubject


@runtime_checkable
class PermissionSubjectBearer(Protocol):
    """Anything a permission profile can bound.

    Deliberately structural rather than a base class: a model does not have to
    inherit from anything to become permissionable, which keeps this open for
    extension without reshaping tables that already exist.
    """

    organization_id: int
    permission_subject_id: str

    @property
    def permission_subject_inactive_reason(self) -> str | None:
        """Why this subject may not be used right now, or ``None`` when it may.

        Part of the Protocol rather than a check inside enforcement, because
        every kind of permissionable thing can be withdrawn and each has its own
        word for it — a Connector is paused, revoked or disconnected; whatever
        comes next will have its own vocabulary. Enforcement asks the subject
        and never learns what kind of thing it is.

        Without this, an approved profile would keep authorising a subject long
        after its authorisation was withdrawn, because the profile and the
        subject are separate records and only the profile was ever consulted.
        """
        ...


def register_permission_subject(
    db: Session, *, organization_id: int, subject_kind: PermissionSubjectKind
) -> PermissionSubject:
    """Create the supertable row a permissionable thing points at.

    Called when the concrete row is created, so the invariant "everything
    permissionable has exactly one subject" holds from the first moment rather
    than being repaired later.
    """
    subject = PermissionSubject(
        organization_id=organization_id, subject_kind=subject_kind.value
    )
    db.add(subject)
    db.flush()
    return subject
