"""
Repository pattern implementation for tenant-scoped database queries.
Ensures complete data isolation between organizations (tenants).
"""

from typing import Any, Generic, List, Optional, Type, TypeVar

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from src.core.models import Base

# Type variable for model classes
ModelType = TypeVar("ModelType", bound=Base)


class TenantRepository(Generic[ModelType]):
    """Base repository with automatic tenant scoping.

    All queries are automatically filtered by organization_id to ensure
    complete tenant isolation and prevent cross-tenant data leaks.

    Example usage:
        >>> repo = TenantRepository(session, CloudAsset, organization_id=123)
        >>> assets = repo.get_all()  # Only returns assets for org 123
        >>> asset = repo.get_by_id(456)  # Returns asset 456 if it belongs to org 123
    """

    def __init__(
        self, session: Session, model_class: Type[ModelType], organization_id: int
    ) -> None:
        """Initialize repository with session, model, and tenant context.

        Args:
            session: SQLAlchemy database session
            model_class: The model class (e.g., CloudAsset, Finding)
            organization_id: The organization ID for tenant scoping

        Raises:
            TypeError: If model_class has no organization_id column. This
                repository's entire contract is "every query is tenant-
                filtered" (see class docstring) — silently returning
                unfiltered rows for a model that happens to lack the column
                is exactly the structural gap the A1 security remediation
                closed (H2): a route gated only by a role check
                (ctx.is_admin()) against a model like LearningImprovementCandidate
                or ServiceTemplate previously fell through _apply_tenant_filter's
                old no-op with zero warning, and any customer's own admin got
                every organisation's rows. Fail loudly here instead, and use
                GlobalRepository below for models that are genuinely
                platform-wide by design.
        """
        if not hasattr(model_class, "organization_id"):
            raise TypeError(
                f"TenantRepository requires a model with an organization_id column; "
                f"{model_class.__name__} has none. If {model_class.__name__} is "
                f"genuinely platform-wide (not tenant-owned), use GlobalRepository "
                f"instead — do not bypass this check."
            )
        self.session = session
        self.model_class = model_class
        self.organization_id = organization_id

    def _apply_tenant_filter(self, stmt: Select) -> Select:
        """Apply organization_id filter to query statement.

        Args:
            stmt: SQLAlchemy select statement

        Returns:
            Select statement with tenant filter applied
        """
        # __init__ already guarantees model_class has organization_id.
        return stmt.where(self.model_class.organization_id == self.organization_id)

    def get_all(self, limit: Optional[int] = None, offset: int = 0) -> List[ModelType]:
        """Get all records for the current tenant.

        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip

        Returns:
            List of model instances
        """
        stmt = select(self.model_class)
        stmt = self._apply_tenant_filter(stmt)

        if limit is not None:
            stmt = stmt.limit(limit).offset(offset)

        result = self.session.execute(stmt)
        return list(result.scalars().all())

    def get_by_id(self, id: int) -> Optional[ModelType]:
        """Get a single record by ID with tenant check.

        Args:
            id: Primary key of the record

        Returns:
            Model instance if found and belongs to tenant, None otherwise
        """
        stmt = select(self.model_class).where(self.model_class.id == id)
        stmt = self._apply_tenant_filter(stmt)

        result = self.session.execute(stmt)
        return result.scalar_one_or_none()

    def create(self, **kwargs: Any) -> ModelType:
        """Create a new record for the current tenant.

        Automatically sets organization_id if the model has this field.

        Args:
            **kwargs: Field values for the new record

        Returns:
            Created model instance
        """
        # Add organization_id if model supports it
        if hasattr(self.model_class, "organization_id"):
            kwargs["organization_id"] = self.organization_id

        instance = self.model_class(**kwargs)
        self.session.add(instance)
        return instance

    def update(self, instance: ModelType, **kwargs: Any) -> ModelType:
        """Update an existing record.

        Verifies the record belongs to the current tenant before updating.

        Args:
            instance: Model instance to update
            **kwargs: Fields to update

        Returns:
            Updated model instance

        Raises:
            ValueError: If instance doesn't belong to current tenant
        """
        # Verify tenant ownership
        if hasattr(instance, "organization_id"):
            if instance.organization_id != self.organization_id:
                raise ValueError(
                    f"Cannot update record: belongs to different organization "
                    f"(expected {self.organization_id}, got {instance.organization_id})"
                )

        # Update fields
        for key, value in kwargs.items():
            setattr(instance, key, value)

        return instance

    def delete(self, instance: ModelType) -> None:
        """Delete a record.

        Verifies the record belongs to the current tenant before deleting.

        Args:
            instance: Model instance to delete

        Raises:
            ValueError: If instance doesn't belong to current tenant
        """
        # Verify tenant ownership
        if hasattr(instance, "organization_id"):
            if instance.organization_id != self.organization_id:
                raise ValueError(
                    f"Cannot delete record: belongs to different organization "
                    f"(expected {self.organization_id}, got {instance.organization_id})"
                )

        self.session.delete(instance)

    def count(self) -> int:
        """Count all records for the current tenant.

        Returns:
            Number of records
        """
        from sqlalchemy import func

        stmt = select(func.count()).select_from(self.model_class)
        stmt = self._apply_tenant_filter(stmt)

        result = self.session.execute(stmt)
        return result.scalar() or 0

    def filter_by(self, **kwargs: Any) -> List[ModelType]:
        """Filter records by field values for the current tenant.

        Args:
            **kwargs: Field names and values to filter by

        Returns:
            List of matching model instances
        """
        stmt = select(self.model_class).filter_by(**kwargs)
        stmt = self._apply_tenant_filter(stmt)

        result = self.session.execute(stmt)
        return list(result.scalars().all())


class GlobalRepository(Generic[ModelType]):
    """Repository for global/system data (not tenant-scoped).

    Use this for models that don't have organization_id or for
    accessing global frameworks, templates, etc.

    Example usage:
        >>> repo = GlobalRepository(session, ComplianceFramework)
        >>> frameworks = repo.get_all()  # Returns all global frameworks
    """

    def __init__(self, session: Session, model_class: Type[ModelType]) -> None:
        """Initialize repository with session and model.

        Args:
            session: SQLAlchemy database session
            model_class: The model class
        """
        self.session = session
        self.model_class = model_class

    def get_all(self, limit: Optional[int] = None, offset: int = 0) -> List[ModelType]:
        """Get all records.

        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip

        Returns:
            List of model instances
        """
        stmt = select(self.model_class)

        if limit is not None:
            stmt = stmt.limit(limit).offset(offset)

        result = self.session.execute(stmt)
        return list(result.scalars().all())

    def get_by_id(self, id: int) -> Optional[ModelType]:
        """Get a single record by ID.

        Args:
            id: Primary key of the record

        Returns:
            Model instance if found, None otherwise
        """
        return self.session.get(self.model_class, id)

    def create(self, **kwargs: Any) -> ModelType:
        """Create a new record.

        Args:
            **kwargs: Field values for the new record

        Returns:
            Created model instance
        """
        instance = self.model_class(**kwargs)
        self.session.add(instance)
        return instance

    def update(self, instance: ModelType, **kwargs: Any) -> ModelType:
        """Update an existing record.

        Args:
            instance: Model instance to update
            **kwargs: Fields to update

        Returns:
            Updated model instance
        """
        for key, value in kwargs.items():
            setattr(instance, key, value)
        return instance

    def delete(self, instance: ModelType) -> None:
        """Delete a record.

        Args:
            instance: Model instance to delete
        """
        self.session.delete(instance)

    def filter_by(self, **kwargs: Any) -> List[ModelType]:
        """Filter records by field values.

        Args:
            **kwargs: Field names and values to filter by

        Returns:
            List of matching model instances
        """
        stmt = select(self.model_class).filter_by(**kwargs)
        result = self.session.execute(stmt)
        return list(result.scalars().all())
