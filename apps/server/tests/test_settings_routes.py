from starlette.requests import Request

from src.api.middleware.tenant_context import TenantContext
from src.api.routes import settings
from src.core.models import User, UserStatus


class DummyResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class DummyDB:
    def __init__(self, current_user: User, query_rows: list[User]):
        self._current_user = current_user
        self._query_rows = query_rows
        self.committed = False

    def get(self, model, key):
        if model is User and key == self._current_user.id:
            return self._current_user
        return None

    def execute(self, _statement):
        return DummyResult(self._query_rows)

    def commit(self):
        self.committed = True


def _request() -> Request:
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/api/v1/settings/users",
        "headers": [],
        "state": {},
    })
    request.state.tenant_context = TenantContext(
        user_id=1,
        organization_id=42,
        email="admin@risklence.test",
        roles=["org_admin"],
        permissions=[],
    )
    return request


def _user(
    *,
    user_id: int,
    email: str,
    title: str | None,
    first_name: str | None,
    last_name: str | None,
    active: bool = True,
    role: str = "member",
) -> User:
    user = User(
        id=user_id,
        organization_id=42,
        email=email,
        role=role,
        permissions=[],
        is_active=active,
        status=UserStatus.ACTIVE,
    )
    user.title = title
    user.first_name = first_name
    user.last_name = last_name
    return user


def test_list_user_directory_returns_active_titled_users():
    admin = _user(user_id=1, email="admin@risklence.test", title="Org Admin", first_name="Ada", last_name="Admin", role="org_admin")
    titled_user = _user(user_id=2, email="owner@risklence.test", title="Head of Platform Engineering", first_name="Alex", last_name="Dahl")
    untitled_user = _user(user_id=3, email="member@risklence.test", title=None, first_name="No", last_name="Title")
    db = DummyDB(admin, [titled_user, untitled_user])

    result = settings.list_user_directory(_request(), db)

    assert len(result) == 1
    assert result[0].title == "Head of Platform Engineering"
    assert result[0].full_name == "Alex Dahl"


def test_patch_user_updates_profile_title_and_name():
    admin = _user(user_id=1, email="admin@risklence.test", title="Org Admin", first_name="Ada", last_name="Admin", role="org_admin")
    target = _user(user_id=2, email="owner@risklence.test", title="Head of Platform Engineering", first_name="Alex", last_name="Dahl")
    db = DummyDB(admin, [target])

    result = settings.patch_user(
        2,
        settings.PatchUserRequest(
            first_name="Jamie",
            last_name="Nielsen",
            title="Head of Payments Operations",
        ),
        _request(),
        db,
    )

    assert db.committed is True
    assert result.first_name == "Jamie"
    assert result.last_name == "Nielsen"
    assert result.title == "Head of Payments Operations"


def test_get_profile_returns_current_user():
    current_user = _user(
        user_id=1,
        email="member@risklence.test",
        title="Head of Payments Operations",
        first_name="Jamie",
        last_name="Nielsen",
    )
    db = DummyDB(current_user, [current_user])

    result = settings.get_profile(_request(), db)

    assert result.email == "member@risklence.test"
    assert result.first_name == "Jamie"
    assert result.title == "Head of Payments Operations"


def test_patch_profile_updates_current_user_title_and_name():
    current_user = _user(
        user_id=1,
        email="member@risklence.test",
        title="Head of Platform Engineering",
        first_name="Alex",
        last_name="Dahl",
    )
    db = DummyDB(current_user, [current_user])

    result = settings.patch_profile(
        settings.PatchProfileRequest(
            first_name="Jamie",
            last_name="Nielsen",
            title="Head of Payments Operations",
        ),
        _request(),
        db,
    )

    assert db.committed is True
    assert result.first_name == "Jamie"
    assert result.last_name == "Nielsen"
    assert result.title == "Head of Payments Operations"
