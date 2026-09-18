from unittest.mock import AsyncMock, patch

import pytest

from mcp_panther.panther_mcp_core.tools.sources import (
    get_http_log_source,
    list_log_sources,
)
from tests.utils.helpers import patch_execute_query

SOURCES_MODULE_PATH = "mcp_panther.panther_mcp_core.tools.sources"

MOCK_LOG_SOURCE = {
    "id": "source-123",
    "label": "Test S3 Source",
    "integrationType": "aws-s3",
    "logTypes": ["AWS.CloudTrail", "AWS.S3ServerAccess"],
    "isHealthy": True,
    "bucketName": "test-bucket",
    "createdAt": "2024-01-01T09:00:00Z",
}

MOCK_HTTP_LOG_SOURCE = {
    "integrationId": "http-source-123",
    "integrationLabel": "Test HTTP Source",
    "logTypes": ["Custom.WebhookData"],
    "logStreamType": "JSON",
    "logStreamTypeOptions": {
        "jsonArrayEnvelopeField": None,
    },
    "authMethod": "Bearer",
    "authBearerToken": "test-token-123",
    "authUsername": None,
    "authPassword": None,
    "authHeaderKey": None,
    "authSecretValue": None,
    "authHmacAlg": None,
}

MOCK_SOURCES_QUERY_RESULT = {
    "sources": {
        "edges": [{"node": MOCK_LOG_SOURCE}],
        "pageInfo": {
            "hasNextPage": False,
            "hasPreviousPage": False,
            "endCursor": "cursor-end",
            "startCursor": "cursor-start",
        },
    }
}


def create_mock_graphql_client():
    """Create a mock GraphQL client for testing."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return mock_client


def create_mock_rest_client():
    """Create a mock REST client for testing."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return mock_client


@pytest.mark.asyncio
@patch_execute_query(SOURCES_MODULE_PATH)
async def test_list_log_sources_success(mock_execute_query):
    """Test successful listing of log sources."""
    mock_execute_query.return_value = MOCK_SOURCES_QUERY_RESULT

    result = await list_log_sources()

    assert result["success"] is True
    assert len(result["sources"]) == 1
    assert result["sources"][0]["id"] == "source-123"
    assert result["sources"][0]["integrationType"] == "aws-s3"
    assert result["total_sources"] == 1
    assert result["has_next_page"] is False
    assert result["has_previous_page"] is False


@pytest.mark.asyncio
@patch_execute_query(SOURCES_MODULE_PATH)
async def test_list_log_sources_with_filters(mock_execute_query):
    """Test listing log sources with filters applied."""
    mock_execute_query.return_value = MOCK_SOURCES_QUERY_RESULT

    result = await list_log_sources(
        log_types=["AWS.CloudTrail"], is_healthy=True, integration_type="aws-s3"
    )

    assert result["success"] is True
    assert len(result["sources"]) == 1
    # The source should match all filters
    assert result["sources"][0]["isHealthy"] is True
    assert result["sources"][0]["integrationType"] == "aws-s3"
    assert "AWS.CloudTrail" in result["sources"][0]["logTypes"]


@pytest.mark.asyncio
@patch_execute_query(SOURCES_MODULE_PATH)
async def test_list_log_sources_filtering_unhealthy(mock_execute_query):
    """Test filtering out unhealthy sources."""
    mock_unhealthy_source = MOCK_LOG_SOURCE.copy()
    mock_unhealthy_source["isHealthy"] = False
    mock_result = {
        "sources": {
            "edges": [{"node": mock_unhealthy_source}],
            "pageInfo": {
                "hasNextPage": False,
                "hasPreviousPage": False,
                "endCursor": None,
                "startCursor": None,
            },
        }
    }

    mock_execute_query.return_value = mock_result

    # Request only healthy sources (default behavior)
    result = await list_log_sources(is_healthy=True)

    assert result["success"] is True
    assert len(result["sources"]) == 0  # Should be filtered out


@pytest.mark.asyncio
@patch_execute_query(SOURCES_MODULE_PATH)
async def test_list_log_sources_with_pagination(mock_execute_query):
    """Test listing log sources with pagination."""
    mock_execute_query.return_value = MOCK_SOURCES_QUERY_RESULT

    result = await list_log_sources(cursor="test-cursor")

    assert result["success"] is True
    # Verify that cursor was passed in the query variables
    mock_execute_query.assert_called_once()
    call_args = mock_execute_query.call_args
    variables = call_args[0][1]  # Second positional arg is variables dict
    assert variables["input"]["cursor"] == "test-cursor"


@pytest.mark.asyncio
@patch_execute_query(SOURCES_MODULE_PATH)
async def test_list_log_sources_error(mock_execute_query):
    """Test handling of errors when listing log sources."""
    mock_execute_query.side_effect = Exception("GraphQL Error")

    result = await list_log_sources()

    assert result["success"] is False
    assert "Failed to fetch log sources" in result["message"]
    assert "GraphQL Error" in result["message"]


@pytest.mark.asyncio
@patch(f"{SOURCES_MODULE_PATH}.get_rest_client")
async def test_get_http_log_source_success(mock_get_client):
    """Test successful retrieval of an HTTP log source."""
    mock_client = create_mock_rest_client()
    mock_client.get.return_value = (MOCK_HTTP_LOG_SOURCE, 200)
    mock_get_client.return_value = mock_client

    result = await get_http_log_source("http-source-123")

    assert result["success"] is True
    assert result["source"]["integrationId"] == "http-source-123"
    assert result["source"]["integrationLabel"] == "Test HTTP Source"
    assert result["source"]["logStreamType"] == "JSON"
    assert result["source"]["authMethod"] == "Bearer"
    # The bearer token must not be disclosed, only its presence
    assert "authBearerToken" not in result["source"]
    assert result["source"]["authSecretsConfigured"]["authBearerToken"] is True
    assert "test-token-123" not in str(result)

    mock_client.get.assert_called_once_with("/log-sources/http/http-source-123")


@pytest.mark.asyncio
@patch(f"{SOURCES_MODULE_PATH}.get_rest_client")
async def test_get_http_log_source_with_hmac_auth(mock_get_client):
    """Test retrieval of HTTP log source with HMAC authentication."""
    mock_http_source_hmac = MOCK_HTTP_LOG_SOURCE.copy()
    mock_http_source_hmac.update(
        {
            "authMethod": "HMAC",
            "authBearerToken": None,
            "authHeaderKey": "X-Signature",
            "authSecretValue": "secret-key-123",
            "authHmacAlg": "sha256",
        }
    )

    mock_client = create_mock_rest_client()
    mock_client.get.return_value = (mock_http_source_hmac, 200)
    mock_get_client.return_value = mock_client

    result = await get_http_log_source("http-source-hmac")

    assert result["success"] is True
    assert result["source"]["authMethod"] == "HMAC"
    assert result["source"]["authHeaderKey"] == "X-Signature"
    assert result["source"]["authHmacAlg"] == "sha256"
    # The shared secret must not be disclosed, only its presence
    assert "authSecretValue" not in result["source"]
    assert "secret-key-123" not in str(result)
    assert result["source"]["authSecretsConfigured"] == {
        "authBearerToken": False,
        "authUsername": False,
        "authPassword": False,
        "authSecretValue": True,
    }


@pytest.mark.asyncio
@patch(f"{SOURCES_MODULE_PATH}.get_rest_client")
async def test_get_http_log_source_with_basic_auth(mock_get_client):
    """Test retrieval of HTTP log source with Basic authentication."""
    mock_http_source_basic = MOCK_HTTP_LOG_SOURCE.copy()
    mock_http_source_basic.update(
        {
            "authMethod": "Basic",
            "authBearerToken": None,
            "authUsername": "testuser",
            "authPassword": "testpass",
            "authHeaderKey": None,
            "authSecretValue": None,
            "authHmacAlg": None,
        }
    )

    mock_client = create_mock_rest_client()
    mock_client.get.return_value = (mock_http_source_basic, 200)
    mock_get_client.return_value = mock_client

    result = await get_http_log_source("http-source-basic")

    assert result["success"] is True
    assert result["source"]["authMethod"] == "Basic"
    # Neither half of the basic auth credential may be disclosed
    assert "authUsername" not in result["source"]
    assert "authPassword" not in result["source"]
    assert "testuser" not in str(result)
    assert "testpass" not in str(result)
    assert result["source"]["authSecretsConfigured"]["authUsername"] is True
    assert result["source"]["authSecretsConfigured"]["authPassword"] is True


@pytest.mark.asyncio
@patch(f"{SOURCES_MODULE_PATH}.get_rest_client")
async def test_get_http_log_source_not_found(mock_get_client):
    """Test handling of HTTP log source not found."""
    mock_client = create_mock_rest_client()
    mock_client.get.side_effect = Exception("HTTP 404: Not Found")
    mock_get_client.return_value = mock_client

    result = await get_http_log_source("nonexistent-source")

    assert result["success"] is False
    assert "Failed to fetch HTTP log source" in result["message"]
    assert "HTTP 404: Not Found" in result["message"]


@pytest.mark.asyncio
@patch(f"{SOURCES_MODULE_PATH}.get_rest_client")
async def test_get_http_log_source_error(mock_get_client):
    """Test handling of general errors when getting HTTP log source."""
    mock_client = create_mock_rest_client()
    mock_client.get.side_effect = Exception("Connection error")
    mock_get_client.return_value = mock_client

    result = await get_http_log_source("http-source-123")

    assert result["success"] is False
    assert "Failed to fetch HTTP log source" in result["message"]
    assert "Connection error" in result["message"]


@pytest.mark.asyncio
@patch(f"{SOURCES_MODULE_PATH}.get_rest_client")
async def test_get_http_log_source_with_json_array_stream_type(mock_get_client):
    """Test HTTP log source with JsonArray stream type and envelope field."""
    mock_http_source_json_array = MOCK_HTTP_LOG_SOURCE.copy()
    mock_http_source_json_array.update(
        {
            "logStreamType": "JsonArray",
            "logStreamTypeOptions": {
                "jsonArrayEnvelopeField": "events",
            },
        }
    )

    mock_client = create_mock_rest_client()
    mock_client.get.return_value = (mock_http_source_json_array, 200)
    mock_get_client.return_value = mock_client

    result = await get_http_log_source("http-source-json-array")

    assert result["success"] is True
    assert result["source"]["logStreamType"] == "JsonArray"
    assert (
        result["source"]["logStreamTypeOptions"]["jsonArrayEnvelopeField"] == "events"
    )


@pytest.mark.asyncio
@patch(f"{SOURCES_MODULE_PATH}.get_rest_client")
async def test_get_http_log_source_redacts_all_credentials(mock_get_client):
    """Test that no credential value is returned, including unknown fields."""
    mock_http_source_all_auth = MOCK_HTTP_LOG_SOURCE.copy()
    mock_http_source_all_auth.update(
        {
            "authBearerToken": "bearer-secret",
            "authUsername": "basic-user",
            "authPassword": "basic-secret",
            "authHeaderKey": "X-Signature",
            "authSecretValue": "hmac-secret",
            "authHmacAlg": "sha256",
            # A credential-bearing field the API may add in the future
            "authFutureToken": "future-secret",
        }
    )

    mock_client = create_mock_rest_client()
    mock_client.get.return_value = (mock_http_source_all_auth, 200)
    mock_get_client.return_value = mock_client

    result = await get_http_log_source("http-source-all-auth")

    assert result["success"] is True
    serialized = str(result)
    for secret in (
        "bearer-secret",
        "basic-user",
        "basic-secret",
        "hmac-secret",
        "future-secret",
    ):
        assert secret not in serialized
    assert "authFutureToken" not in result["source"]
    # Non-credential configuration is still available
    assert result["source"]["authHeaderKey"] == "X-Signature"
    assert result["source"]["authHmacAlg"] == "sha256"
    assert result["source"]["authSecretsConfigured"] == {
        "authBearerToken": True,
        "authUsername": True,
        "authPassword": True,
        "authSecretValue": True,
    }


@pytest.mark.asyncio
@patch(f"{SOURCES_MODULE_PATH}.get_rest_client")
async def test_get_http_log_source_unexpected_response_shape(mock_get_client):
    """Test that a non-dict API response does not leak through unredacted."""
    mock_client = create_mock_rest_client()
    mock_client.get.return_value = (["unexpected", "payload"], 200)
    mock_get_client.return_value = mock_client

    result = await get_http_log_source("http-source-123")

    assert result["success"] is True
    assert result["source"] == {}
