import pytest

from mcp_panther.panther_mcp_core.client import validate_rest_path
from mcp_panther.panther_mcp_core.tools.users import (
    get_user,
    list_users,
)
from tests.utils.helpers import patch_rest_client

MOCK_USER = {
    "id": "user-123",
    "email": "user@example.com",
    "givenName": "John",
    "familyName": "Doe",
    "enabled": True,
    "roles": ["Admin"],
    "createdAt": "2024-11-14T17:09:49.841715953Z",
    "lastModified": "2024-11-14T17:09:49.841716265Z",
}

MOCK_USER_STANDARD = {
    **MOCK_USER,
    "id": "user-456",
    "email": "standard@example.com",
    "givenName": "Jane",
    "familyName": "Smith",
    "roles": ["Analyst"],
}

MOCK_USERS_RESPONSE = {"users": [MOCK_USER, MOCK_USER_STANDARD]}

USERS_MODULE_PATH = "mcp_panther.panther_mcp_core.tools.users"


@pytest.mark.asyncio
@patch_rest_client(USERS_MODULE_PATH)
async def test_get_user_success(mock_rest_client):
    """Test successful retrieval of a single user."""
    mock_rest_client.get.return_value = (MOCK_USER, 200)

    result = await get_user(MOCK_USER["id"])

    assert result["success"] is True
    assert result["user"]["id"] == MOCK_USER["id"]
    assert result["user"]["email"] == MOCK_USER["email"]
    assert result["user"]["givenName"] == MOCK_USER["givenName"]
    assert result["user"]["familyName"] == MOCK_USER["familyName"]
    assert result["user"]["roles"] == MOCK_USER["roles"]

    mock_rest_client.get.assert_called_once()
    args, kwargs = mock_rest_client.get.call_args
    assert args[0] == f"/users/{MOCK_USER['id']}"


@pytest.mark.asyncio
@patch_rest_client(USERS_MODULE_PATH)
async def test_get_user_not_found(mock_rest_client):
    """Test handling of non-existent user."""
    mock_rest_client.get.return_value = ({}, 404)

    result = await get_user("nonexistent-user")

    assert result["success"] is False
    assert "No user found with ID" in result["message"]


@pytest.mark.asyncio
@patch_rest_client(USERS_MODULE_PATH)
async def test_get_user_error(mock_rest_client):
    """Test handling of errors when getting user by ID."""
    mock_rest_client.get.side_effect = Exception("Test error")

    result = await get_user(MOCK_USER["id"])

    assert result["success"] is False
    assert "Failed to get user details" in result["message"]


# Note: The list_users function uses GraphQL (_execute_query) instead of REST,
# so we need to mock that differently. For now, we'll create a basic test structure.
@pytest.mark.asyncio
async def test_list_users_structure():
    """Test that the list_users function has the correct structure."""
    # This is a basic structure test since the function uses GraphQL
    # In a real implementation, you'd want to mock _execute_query
    assert callable(list_users)

    # Test that the function signature is correct
    import inspect

    sig = inspect.signature(list_users)
    assert len(sig.parameters) == 2  # cursor and limit parameters expected

    # Check parameter names and defaults
    params = list(sig.parameters.keys())
    assert "cursor" in params
    assert "limit" in params
    assert sig.parameters["cursor"].default is None
    assert sig.parameters["limit"].default == 60


# (injected id, expected path or None when the id must be rejected outright)
PATH_INJECTION_CASES = [
    ("../api-tokens/self", None),
    ("user-123/../../api-tokens/self", None),
    ("..", None),
    ("%2e%2e", None),
    ("..%2fapi-tokens", "/users/..%252fapi-tokens"),
    ("user-123?limit=1#", "/users/user-123%3Flimit%3D1%23"),
    ("a\r\nX-Injected: 1", "/users/a%0D%0AX-Injected%3A%201"),
]


@pytest.mark.asyncio
@patch_rest_client(USERS_MODULE_PATH)
async def test_get_user_rejects_path_injection(mock_rest_client):
    """An injected ID cannot retarget the request at another REST endpoint."""
    for malicious_id, expected_path in PATH_INJECTION_CASES:
        mock_rest_client.get.reset_mock()
        mock_rest_client.get.return_value = (MOCK_USER, 200)

        result = await get_user(malicious_id)

        if expected_path is None:
            # Rejected outright: no request is issued at all.
            assert not mock_rest_client.get.called, malicious_id
            assert result["success"] is False, malicious_id
            continue

        # Otherwise the ID survives only as one opaque segment under /users,
        # and the path the client would build is still accepted by the
        # client-side validator.
        path = mock_rest_client.get.call_args[0][0]
        assert path == expected_path, malicious_id
        assert validate_rest_path(path) == expected_path
