"""Regression fixture for the actual H2 mechanism: the checker's model
classification (hasattr(model, "organization_id"), identical to
TenantRepository.__init__'s own guard) must correctly separate a genuinely
global model (no violation possible — GlobalRepository's domain) from a
tenant-scoped one, in the identical unfiltered-query shape. This is what
would have caught H2 (the classification failure behind both C1 and H1),
not H1/C1's own role-gate choices individually — those are already covered
by test_learning_routes.py / test_template_governance_routes.py."""

from sqlalchemy.orm import Session

from src.core.models import Organization, User


def get_organization_unfiltered(db: Session, organization_id: int) -> Organization | None:
    # Organization has no organization_id column — it IS the tenant root.
    # Correctly excluded from this check entirely; not a violation.
    return db.query(Organization).filter(Organization.id == organization_id).first()


def get_user_unfiltered(db: Session, user_id: int) -> User | None:
    # User DOES have organization_id. Querying by a client-supplied user_id
    # with no org check and no ctx-derived self-lookup is exactly the
    # H1/C1-shaped gap. Must be flagged.
    return db.query(User).filter(User.id == user_id).first()
