"""Tests for the tool annotations MCP hosts use to gate approval.

Hosts commonly auto-approve tools advertised with ``readOnlyHint``. A tool that
changes server state must therefore never carry that hint, or it escapes the
host's consent prompt entirely.
"""

import inspect
import re

import pytest
from fastmcp import Client
from graphql import OperationType

from mcp_panther.panther_mcp_core import queries
from mcp_panther.panther_mcp_core.tools import alerts
from mcp_panther.server import mcp

# Alert tools that change server state and must be gated like each other.
STATE_CHANGING_ALERT_TOOLS = [
    "add_alert_comment",
    "bulk_update_alerts",
    "start_ai_alert_triage",
    "update_alert_assignee",
    "update_alert_status",
]


def _mutation_constants() -> set[str]:
    """Names in queries.py whose GraphQL document is a mutation.

    Derived from the parsed operation type rather than the constant name:
    several mutations are named ``*_QUERY``, so matching on the name alone
    would miss them.
    """
    names = set()
    for name, document in vars(queries).items():
        definitions = getattr(document, "definitions", None) or ()
        if any(
            getattr(definition, "operation", None) is OperationType.MUTATION
            for definition in definitions
        ):
            names.add(name)
    return names


def _registered_name(func) -> str:
    metadata = getattr(func, "_mcp_tool_metadata", {})
    return metadata.get("name") or func.__name__


async def _registered_annotations() -> dict:
    """Return the annotations for every tool as an MCP host sees them."""
    async with Client(mcp) as client:
        return {tool.name: tool.annotations for tool in await client.list_tools()}


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", STATE_CHANGING_ALERT_TOOLS)
async def test_state_changing_alert_tools_are_not_read_only(tool_name):
    annotations = (await _registered_annotations())[tool_name]

    assert annotations is not None
    assert annotations.readOnlyHint is not True
    assert annotations.destructiveHint is True


@pytest.mark.asyncio
async def test_start_ai_alert_triage_is_advertised_as_state_changing():
    """The tool runs the aiSummarizeAlert mutation, so it is not read-only.

    The mutation stores a new AI inference stream against the alert, which
    get_ai_alert_triage_summary later returns as the alert's triage summary.
    """
    annotations = (await _registered_annotations())["start_ai_alert_triage"]

    assert annotations.readOnlyHint is False
    assert annotations.destructiveHint is True


@pytest.mark.asyncio
async def test_no_alert_tool_running_a_mutation_is_read_only():
    """Sweep the alert tools: running a GraphQL mutation rules out read-only."""
    annotations_by_name = await _registered_annotations()
    mutation_pattern = re.compile(
        r"\b(?:%s)\b" % "|".join(sorted(_mutation_constants()))
    )

    mutating_tools = []
    for func in vars(alerts).values():
        if not callable(func) or not hasattr(func, "_mcp_tool_metadata"):
            continue
        if mutation_pattern.search(inspect.getsource(func)):
            mutating_tools.append(_registered_name(func))

    # Guards the sweep itself: if the detection stops finding anything, the test
    # would pass vacuously.
    assert "start_ai_alert_triage" in mutating_tools

    read_only = [
        name
        for name in mutating_tools
        if getattr(annotations_by_name.get(name), "readOnlyHint", None) is True
    ]
    assert read_only == []
