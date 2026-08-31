import time
from unittest.mock import patch

import pytest
from pydantic import ValidationError, validate_call

from mcp_panther.panther_mcp_core.tools.data_lake import (
    MAX_SQL_LENGTH,
    _cancel_data_lake_query,
    _has_p_event_time_filter,
    _sql_string_literal,
    get_alert_event_stats,
    query_data_lake,
)
from tests.utils.helpers import patch_execute_query

DATA_LAKE_MODULE_PATH = "mcp_panther.panther_mcp_core.tools.data_lake"

MOCK_QUERY_ID = "query-123456789"


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_success(mock_execute_query):
    """Test successful execution of a data lake query."""
    mock_execute_query.return_value = {"executeDataLakeQuery": {"id": MOCK_QUERY_ID}}
    sql = "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP()) LIMIT 10"
    with patch(f"{DATA_LAKE_MODULE_PATH}._get_data_lake_query_results") as mock_res:
        mock_res.return_value = {
            "success": True,
            "status": "succeeded",
            "results": [],
            "column_info": {},
            "stats": {},
            "has_next_page": False,
            "next_cursor": None,
            "message": "Query executed successfully",
            "query_id": MOCK_QUERY_ID,
        }
        result = await query_data_lake(sql)

    assert result["success"] is True
    assert result["status"] == "succeeded"
    assert result["query_id"] == MOCK_QUERY_ID

    mock_execute_query.assert_called_once()
    call_args = mock_execute_query.call_args[0][
        1
    ]  # Second positional arg is variables dict
    assert call_args["input"]["sql"] == sql
    assert call_args["input"]["databaseName"] == "panther_logs.public"


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_custom_database(mock_execute_query):
    """Test executing a data lake query with a custom database."""
    mock_execute_query.return_value = {"executeDataLakeQuery": {"id": MOCK_QUERY_ID}}
    sql = "SELECT * FROM my_custom_table WHERE p_event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP()) LIMIT 10"
    custom_db = "custom_database"
    with patch(f"{DATA_LAKE_MODULE_PATH}._get_data_lake_query_results") as mock_res:
        mock_res.return_value = {
            "success": True,
            "status": "succeeded",
            "results": [],
            "column_info": {},
            "stats": {},
            "has_next_page": False,
            "next_cursor": None,
            "message": "Query executed successfully",
            "query_id": MOCK_QUERY_ID,
        }
        result = await query_data_lake(sql, database_name=custom_db)

    assert result["success"] is True
    assert result["status"] == "succeeded"
    assert result["query_id"] == MOCK_QUERY_ID

    call_args = mock_execute_query.call_args[0][1]
    assert call_args["input"]["databaseName"] == custom_db


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_error(mock_execute_query):
    """Test handling of errors when executing a data lake query."""
    mock_execute_query.side_effect = Exception("Test error")

    sql = "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP()) LIMIT 10"
    result = await query_data_lake(sql)

    assert result["success"] is False
    assert "Failed to execute data lake query" in result["message"]
    assert (
        result["query_id"] is None
    )  # No query_id when error occurs before query execution


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_missing_event_time(mock_execute_query):
    """Test that queries without p_event_time filter are rejected."""
    sql = "SELECT * FROM panther_logs.public.aws_cloudtrail LIMIT 10"
    result = await query_data_lake(sql)

    assert result["success"] is False
    assert (
        "Query must include a time filter: either `p_event_time` condition or Panther macro"
        in result["message"]
    )
    assert result["query_id"] is None  # No query_id when validation fails
    mock_execute_query.assert_not_called()


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_with_event_time(mock_execute_query):
    """Test that queries with p_event_time filter are accepted."""
    mock_execute_query.return_value = {"executeDataLakeQuery": {"id": MOCK_QUERY_ID}}

    # Test various valid filter patterns
    valid_queries = [
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP()) LIMIT 10",
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE (p_event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP()) AND other_condition) LIMIT 10",
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE other_condition AND p_event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP()) LIMIT 10",
        # Test table-qualified p_event_time fields
        "SELECT * FROM panther_logs.public.aws_cloudtrail t WHERE t.p_event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP()) LIMIT 10",
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE aws_cloudtrail.p_event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP()) LIMIT 10",
        "SELECT * FROM panther_logs.public.aws_cloudtrail t1 WHERE t1.p_event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP()) LIMIT 10",
        "SELECT * FROM panther_logs.public.aws_cloudtrail t1 WHERE other_condition AND t1.p_event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP()) LIMIT 10",
        # Test Panther time macros
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_occurs_since('1 d') LIMIT 10",
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_occurs_between('2024-01-01', '2024-01-02') LIMIT 10",
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_occurs_around('2024-01-01 10:00:00', '10 m') LIMIT 10",
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_occurs_after('2024-01-01') AND other_condition LIMIT 10",
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE other_condition AND p_occurs_before('2024-01-01') LIMIT 10",
    ]

    with patch(f"{DATA_LAKE_MODULE_PATH}._get_data_lake_query_results") as mock_res:
        mock_res.return_value = {
            "success": True,
            "status": "succeeded",
            "results": [],
            "column_info": {},
            "stats": {},
            "has_next_page": False,
            "next_cursor": None,
            "message": "Query executed successfully",
            "query_id": MOCK_QUERY_ID,
        }
        for sql in valid_queries:
            result = await query_data_lake(sql)
            assert result["success"] is True, f"Query failed: {sql}"
            assert result["status"] == "succeeded"
            assert result["query_id"] == MOCK_QUERY_ID
            mock_execute_query.assert_called_once()
            mock_execute_query.reset_mock()


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_invalid_event_time_usage(mock_execute_query):
    """Test that queries with invalid p_event_time usage are rejected."""
    mock_execute_query.return_value = {"executeDataLakeQuery": {"id": MOCK_QUERY_ID}}

    invalid_queries = [
        # p_event_time in SELECT
        "SELECT p_event_time FROM panther_logs.public.aws_cloudtrail LIMIT 10",
        # p_event_time as a value
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE other_column = p_event_time LIMIT 10",
        # p_event_time without WHERE/AND
        "SELECT * FROM panther_logs.public.aws_cloudtrail LIMIT 10",
        # p_event_time in a subquery
        "SELECT * FROM (SELECT p_event_time FROM panther_logs.public.aws_cloudtrail) LIMIT 10",
        # Invalid table-qualified p_event_time usage
        "SELECT t.p_event_time FROM panther_logs.public.aws_cloudtrail t LIMIT 10",
        "SELECT * FROM panther_logs.public.aws_cloudtrail t WHERE other_column = t.p_event_time LIMIT 10",
        "SELECT * FROM (SELECT t.p_event_time FROM panther_logs.public.aws_cloudtrail t) LIMIT 10",
    ]

    for sql in invalid_queries:
        result = await query_data_lake(sql)
        assert result["success"] is False, f"Query should have failed: {sql}"
        assert (
            "Query must include a time filter: either `p_event_time` condition or Panther macro"
            in result["message"]
        )
        assert result["query_id"] is None  # No query_id when validation fails
        mock_execute_query.assert_not_called()


@pytest.mark.parametrize(
    "sql_lower,expected",
    [
        ("select * from t where p_event_time >= x", True),
        ("select * from t where a = 1 and t.p_event_time < x", True),
        ("select * from t where a.b.c.p_event_time between x and y", True),
        ("select * from t where (p_event_time = x and y)", True),
        ("select p_event_time from t", False),
        ("select * from t where other_column = p_event_time", False),
        ("select * from t where other_column = t.p_event_time", False),
        ("p_event_time >= x", False),  # no where/and keyword
        ("select * from t wherep_event_time >= x", False),  # keyword not delimited
        ("", False),
    ],
)
def test_has_p_event_time_filter(sql_lower, expected):
    """The time filter check only accepts p_event_time comparisons after WHERE/AND."""
    assert _has_p_event_time_filter(sql_lower) is expected


def test_has_p_event_time_filter_is_not_vulnerable_to_redos():
    """The time filter check must run in linear time on adversarial input.

    The previous pattern bridged WHERE/AND and p_event_time with a lazy `.*?`
    followed by an ambiguous `(?:[\\w.]+\\.)?` group, which backtracked
    super-linearly and blocked the event loop for minutes on this input.
    """
    payload = "and " + "a." * 100_000

    start = time.perf_counter()
    result = _has_p_event_time_filter(payload)
    elapsed = time.perf_counter() - start

    assert result is False
    assert elapsed < 1.0, f"Time filter check took {elapsed:.3f}s on 200KB of input"


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_rejects_oversized_query(mock_execute_query):
    """Test that queries longer than MAX_SQL_LENGTH are rejected before validation."""
    sql = (
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_event_time >= x -- "
        + "a" * MAX_SQL_LENGTH
    )

    result = await query_data_lake(sql)

    assert result["success"] is False
    assert "too long" in result["message"]
    assert result["query_id"] is None
    mock_execute_query.assert_not_called()


@pytest.mark.asyncio
async def test_query_data_lake_sql_length_annotation_validates():
    """The sql annotation must bound the query length on the MCP call path too.

    The test above calls the coroutine directly, which skips the schema validation
    an MCP client goes through. This exercises the annotated constraint itself.
    """
    validated = validate_call(query_data_lake.__wrapped__)

    with pytest.raises(ValidationError):
        await validated(sql="a" * (MAX_SQL_LENGTH + 1))


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_cancel_data_lake_query_success(mock_execute_query):
    """Test successful cancellation of a data lake query."""
    mock_response = {"cancelDataLakeQuery": {"id": "query123"}}
    mock_execute_query.return_value = mock_response

    result = await _cancel_data_lake_query("query123")

    assert result["success"] is True
    assert result["query_id"] == "query123"
    assert "Successfully cancelled" in result["message"]

    # Verify correct GraphQL call
    call_args = mock_execute_query.call_args[0][1]
    assert call_args["input"]["id"] == "query123"


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_cancel_data_lake_query_not_found(mock_execute_query):
    """Test cancellation of a non-existent query."""
    mock_execute_query.side_effect = Exception("Query not found")

    result = await _cancel_data_lake_query("nonexistent")

    assert result["success"] is False
    assert "not found" in result["message"]
    assert "already completed or been cancelled" in result["message"]


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_cancel_data_lake_query_cannot_cancel(mock_execute_query):
    """Test cancellation of a query that cannot be cancelled."""
    mock_execute_query.side_effect = Exception("Query cannot be cancelled")

    result = await _cancel_data_lake_query("completed_query")

    assert result["success"] is False
    assert "cannot be cancelled" in result["message"]
    assert "Only running queries" in result["message"]


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_cancel_data_lake_query_permission_error(mock_execute_query):
    """Test cancellation with permission error."""
    mock_execute_query.side_effect = Exception("Permission denied")

    result = await _cancel_data_lake_query("query123")

    assert result["success"] is False
    assert "Permission denied" in result["message"]


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_cancel_data_lake_query_no_id_returned(mock_execute_query):
    """Test cancellation when no ID is returned."""
    mock_response = {"cancelDataLakeQuery": {}}
    mock_execute_query.return_value = mock_response

    result = await _cancel_data_lake_query("query123")

    assert result["success"] is False
    assert "No query ID returned" in result["message"]


# SQL Literal Handling Tests


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_preserves_string_literals(
    mock_execute_query,
):
    """String literals must reach the data lake unchanged, reserved words included."""
    mock_execute_query.return_value = {"executeDataLakeQuery": {"id": MOCK_QUERY_ID}}

    # 'select' and 'union' are data here, and must not be rewritten as identifiers
    input_sql = (
        "SELECT eventName FROM panther_logs.public.aws_cloudtrail "
        "WHERE p_event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP()) "
        "AND eventName IN ('select', 'union') LIMIT 10"
    )

    with patch(f"{DATA_LAKE_MODULE_PATH}._get_data_lake_query_results") as mock_results:
        mock_results.return_value = {
            "success": True,
            "status": "succeeded",
            "results": [],
            "column_info": {},
            "stats": {},
            "has_next_page": False,
            "next_cursor": None,
            "message": "Query executed successfully",
            "query_id": MOCK_QUERY_ID,
        }

        result = await query_data_lake(input_sql)

    assert result["success"] is True

    submitted_sql = mock_execute_query.call_args[0][1]["input"]["sql"]
    assert submitted_sql == input_sql
    assert '"select"' not in submitted_sql
    assert '"union"' not in submitted_sql


# get_alert_event_stats Input Validation Tests


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_get_alert_event_stats_builds_quoted_query(mock_execute_query):
    """Alert IDs and dates are emitted as quoted literals inside the generated SQL."""
    mock_execute_query.return_value = {"executeDataLakeQuery": {"id": MOCK_QUERY_ID}}

    with patch(f"{DATA_LAKE_MODULE_PATH}._get_data_lake_query_results") as mock_results:
        mock_results.return_value = {
            "success": True,
            "status": "succeeded",
            "results": [],
            "column_info": {},
            "stats": {},
            "has_next_page": False,
            "next_cursor": None,
            "message": "Query executed successfully",
            "query_id": MOCK_QUERY_ID,
        }

        result = await get_alert_event_stats(
            alert_ids=["alert-123", "df1eb66cede030f1a6d29362ba437178"],
            start_date="2024-03-20T00:00:00Z",
            end_date="2024-03-21T00:00:00Z",
        )

    assert result["success"] is True

    submitted_sql = mock_execute_query.call_args[0][1]["input"]["sql"]
    assert (
        "cs.p_alert_id IN ('alert-123', 'df1eb66cede030f1a6d29362ba437178')"
        in submitted_sql
    )
    assert (
        "cs.p_event_time BETWEEN '2024-03-20T00:00:00Z' AND '2024-03-21T00:00:00Z'"
        in submitted_sql
    )


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_get_alert_event_stats_rejects_injected_alert_ids(mock_execute_query):
    """Alert IDs that could alter query grammar are rejected before any query runs."""
    malicious_ids = [
        "x') OR p_alert_id IS NOT NULL UNION SELECT 1 --",
        "abc' OR '1'='1",
        "abc123; DROP TABLE foo",
        "abc 123",
        'abc"123',
        "abc\\123",
        "",
    ]

    for malicious_id in malicious_ids:
        with pytest.raises(ValueError, match="Invalid alert ID"):
            await get_alert_event_stats(alert_ids=[malicious_id])

    mock_execute_query.assert_not_called()


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_get_alert_event_stats_rejects_injected_dates(mock_execute_query):
    """Date parameters must be valid ISO-8601 before being placed in the query."""
    malicious_dates = [
        "2024-01-01' OR '1'='1",
        "2024-01-01' UNION SELECT * FROM panther_logs.public.aws_cloudtrail --",
        "not-a-date",
        # datetime.fromisoformat() accepts any single character as the date/time
        # separator, so these parse as ISO-8601 but carry SQL metacharacters
        "2024-01-01'00:00:00",
        '2024-01-01"00:00:00',
        "2024-01-01\\00:00:00",
        "2024-01-01;00:00:00",
        "2024-01-01\n00:00:00",
    ]

    for malicious_date in malicious_dates:
        with pytest.raises(ValueError, match="Invalid date format"):
            await get_alert_event_stats(
                alert_ids=["alert-123"], start_date=malicious_date
            )

        with pytest.raises(ValueError, match="Invalid date format"):
            await get_alert_event_stats(
                alert_ids=["alert-123"], end_date=malicious_date
            )

    mock_execute_query.assert_not_called()


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_get_alert_event_stats_rejects_empty_alert_ids(mock_execute_query):
    """An empty alert ID list would otherwise produce a malformed IN () clause."""
    with pytest.raises(ValueError, match="At least one alert ID"):
        await get_alert_event_stats(alert_ids=[])

    mock_execute_query.assert_not_called()


@pytest.mark.asyncio
async def test_get_alert_event_stats_parameter_annotations_validate():
    """The parameter annotations must reject payloads on the MCP call path too.

    The tests above call the coroutine directly, which skips the schema validation
    an MCP client goes through. This exercises the annotated validators themselves.
    """
    validated = validate_call(get_alert_event_stats.__wrapped__)

    with pytest.raises(ValidationError, match="Invalid alert ID"):
        await validated(alert_ids=["x') OR p_alert_id IS NOT NULL --"])

    with pytest.raises(ValidationError, match="Invalid date format"):
        await validated(alert_ids=["alert-123"], start_date="2024-01-01' OR '1'='1")

    with pytest.raises(ValidationError, match="Invalid date format"):
        await validated(alert_ids=["alert-123"], end_date="2024-01-01'00:00:00")

    with pytest.raises(ValidationError):
        await validated(alert_ids=[])


def test_sql_string_literal_escapes_quotes_and_backslashes():
    """Quotes and backslashes must not be able to terminate the literal."""
    assert _sql_string_literal("alert-123") == "'alert-123'"
    assert _sql_string_literal("a'b") == "'a''b'"
    # Snowflake honours backslash escapes inside string constants, so a trailing
    # backslash would otherwise swallow the closing quote
    assert _sql_string_literal("abc\\") == "'abc\\\\'"
    assert _sql_string_literal("a\\'b") == "'a\\\\''b'"


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_with_cursor_pagination(
    mock_execute_query,
):
    """Test that query_data_lake supports cursor-based pagination."""
    mock_execute_query.return_value = {"executeDataLakeQuery": {"id": MOCK_QUERY_ID}}

    cursor = "pagination_cursor_123"
    test_sql = (
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_occurs_since('1 d')"
    )

    # Mock the query results function to return paginated response
    with patch(f"{DATA_LAKE_MODULE_PATH}._get_data_lake_query_results") as mock_results:
        mock_results.return_value = {
            "success": True,
            "status": "succeeded",
            "results": [{"event": "test_data"}],
            "results_truncated": False,
            "total_rows_available": 1,
            "column_info": {"order": ["event"], "types": {"event": "string"}},
            "stats": {"bytes_scanned": 1024},
            "has_next_page": True,
            "next_cursor": "next_cursor_456",
            "message": "Query executed successfully",
            "query_id": MOCK_QUERY_ID,
        }

        result = await query_data_lake(test_sql, cursor=cursor, max_rows=50)

    # Verify the function returns success with pagination info
    assert result["success"] is True
    assert result["status"] == "succeeded"
    assert result["has_next_page"] is True
    assert result["next_cursor"] == "next_cursor_456"

    # Verify the cursor was passed to the results function
    mock_results.assert_called_once_with(
        query_id=MOCK_QUERY_ID, max_rows=50, cursor=cursor
    )


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_first_page_without_cursor(
    mock_execute_query,
):
    """Test that query_data_lake works without cursor for first page."""
    mock_execute_query.return_value = {"executeDataLakeQuery": {"id": MOCK_QUERY_ID}}

    test_sql = (
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_occurs_since('1 d')"
    )

    # Mock the query results function to return first page response
    with patch(f"{DATA_LAKE_MODULE_PATH}._get_data_lake_query_results") as mock_results:
        mock_results.return_value = {
            "success": True,
            "status": "succeeded",
            "results": [{"event": "test_data"}],
            "results_truncated": False,
            "total_rows_available": 1,
            "column_info": {"order": ["event"], "types": {"event": "string"}},
            "stats": {"bytes_scanned": 1024},
            "has_next_page": False,
            "next_cursor": None,
            "message": "Query executed successfully",
            "query_id": MOCK_QUERY_ID,
        }

        result = await query_data_lake(test_sql, max_rows=100)

    # Verify the function returns success with first page info
    assert result["success"] is True
    assert result["status"] == "succeeded"
    assert result["has_next_page"] is False
    assert result["next_cursor"] is None

    # Verify no cursor was passed to the results function
    mock_results.assert_called_once_with(
        query_id=MOCK_QUERY_ID, max_rows=100, cursor=None
    )


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_pagination_complete_workflow(
    mock_execute_query,
):
    """Test complete pagination workflow from first page to last page."""
    mock_execute_query.return_value = {"executeDataLakeQuery": {"id": MOCK_QUERY_ID}}

    test_sql = "SELECT eventName FROM panther_logs.public.aws_cloudtrail WHERE p_occurs_since('1 d')"

    # Mock first page response
    with patch(f"{DATA_LAKE_MODULE_PATH}._get_data_lake_query_results") as mock_results:
        # First call - no cursor, has more pages
        mock_results.return_value = {
            "success": True,
            "status": "succeeded",
            "results": [{"eventName": "GetObject"}, {"eventName": "PutObject"}],
            "results_truncated": False,
            "total_rows_available": 2,
            "column_info": {"order": ["eventName"], "types": {"eventName": "string"}},
            "stats": {"bytes_scanned": 1024},
            "has_next_page": True,
            "next_cursor": "page2_cursor",
            "message": "Query executed successfully",
            "query_id": MOCK_QUERY_ID,
        }

        first_page = await query_data_lake(test_sql, max_rows=2)

        # Verify first page response
        assert first_page["success"] is True
        assert first_page["has_next_page"] is True
        assert first_page["next_cursor"] == "page2_cursor"
        assert len(first_page["results"]) == 2

        # Mock second page response
        mock_results.return_value = {
            "success": True,
            "status": "succeeded",
            "results": [{"eventName": "AssumeRole"}],
            "results_truncated": False,
            "total_rows_available": 1,
            "column_info": {"order": ["eventName"], "types": {"eventName": "string"}},
            "stats": {"bytes_scanned": 512},
            "has_next_page": False,
            "next_cursor": None,
            "message": "Query executed successfully",
            "query_id": MOCK_QUERY_ID,
        }

        second_page = await query_data_lake(test_sql, cursor="page2_cursor", max_rows=2)

        # Verify second page response (last page)
        assert second_page["success"] is True
        assert second_page["has_next_page"] is False
        assert second_page["next_cursor"] is None
        assert len(second_page["results"]) == 1


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_legacy_truncation_behavior(
    mock_execute_query,
):
    """Test legacy truncation behavior for non-paginated requests."""
    mock_execute_query.return_value = {"executeDataLakeQuery": {"id": MOCK_QUERY_ID}}

    test_sql = (
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_occurs_since('1 d')"
    )

    # Mock response that would exceed max_rows
    with patch(f"{DATA_LAKE_MODULE_PATH}._get_data_lake_query_results") as mock_results:
        mock_results.return_value = {
            "success": True,
            "status": "succeeded",
            "results": [{"event": f"data_{i}"} for i in range(5)],  # 5 results
            "results_truncated": True,  # Would be truncated to 3
            "total_rows_available": 5,
            "column_info": {"order": ["event"], "types": {"event": "string"}},
            "stats": {"bytes_scanned": 2048},
            "has_next_page": True,
            "next_cursor": "truncated_cursor",
            "message": "Query executed successfully",
            "query_id": MOCK_QUERY_ID,
        }

        result = await query_data_lake(test_sql, max_rows=3)  # No cursor = legacy mode

        # Verify truncation behavior is preserved
        assert result["success"] is True
        assert result["results_truncated"] is True
        assert result["total_rows_available"] == 5
        assert result["has_next_page"] is True


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_pagination_with_empty_results(
    mock_execute_query,
):
    """Test pagination behavior when query returns no results."""
    mock_execute_query.return_value = {"executeDataLakeQuery": {"id": MOCK_QUERY_ID}}

    test_sql = "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_occurs_since('1 d') AND eventName = 'NonExistentEvent'"

    with patch(f"{DATA_LAKE_MODULE_PATH}._get_data_lake_query_results") as mock_results:
        mock_results.return_value = {
            "success": True,
            "status": "succeeded",
            "results": [],
            "results_truncated": False,
            "total_rows_available": 0,
            "column_info": {"order": [], "types": {}},
            "stats": {"bytes_scanned": 0},
            "has_next_page": False,
            "next_cursor": None,
            "message": "Query executed successfully",
            "query_id": MOCK_QUERY_ID,
        }

        result = await query_data_lake(test_sql, max_rows=10)

        # Verify empty results handling
        assert result["success"] is True
        assert result["results"] == []
        assert result["has_next_page"] is False
        assert result["next_cursor"] is None
        assert result["results_truncated"] is False
        assert result["total_rows_available"] == 0


@pytest.mark.asyncio
@patch_execute_query(DATA_LAKE_MODULE_PATH)
async def test_query_data_lake_max_rows_parameter_limits(
    mock_execute_query,
):
    """Test that max_rows parameter respects limits and defaults."""
    mock_execute_query.return_value = {"executeDataLakeQuery": {"id": MOCK_QUERY_ID}}

    test_sql = (
        "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_occurs_since('1 d')"
    )

    with patch(f"{DATA_LAKE_MODULE_PATH}._get_data_lake_query_results") as mock_results:
        mock_results.return_value = {
            "success": True,
            "status": "succeeded",
            "results": [{"event": "test"}],
            "results_truncated": False,
            "total_rows_available": 1,
            "column_info": {"order": ["event"], "types": {"event": "string"}},
            "stats": {"bytes_scanned": 100},
            "has_next_page": False,
            "next_cursor": None,
            "message": "Query executed successfully",
            "query_id": MOCK_QUERY_ID,
        }

        # Test default max_rows (should be 100)
        await query_data_lake(test_sql)
        mock_results.assert_called_with(
            query_id=MOCK_QUERY_ID, max_rows=100, cursor=None
        )

        # Test custom max_rows
        await query_data_lake(test_sql, max_rows=50)
        mock_results.assert_called_with(
            query_id=MOCK_QUERY_ID, max_rows=50, cursor=None
        )

        # Test with cursor
        await query_data_lake(test_sql, max_rows=25, cursor="test_cursor")
        mock_results.assert_called_with(
            query_id=MOCK_QUERY_ID, max_rows=25, cursor="test_cursor"
        )
