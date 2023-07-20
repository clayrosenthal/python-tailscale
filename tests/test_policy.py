"""Asynchronous client for the Tailscale API."""
# pylint: disable=protected-access
# pyright: reportGeneralTypeIssues=false
import json

import aiohttp
import pytest
from aresponses import ResponsesMockServer

from tailscale import Tailscale
from tailscale.models import Policy

test_policy_1 = {
    "acls": [
        {
            "action": "accept",
            "src": ["10.10.10.10/10"],
            "dst": ["group:test"],
        },
        {
            "action": "accept",
            "src": ["autogroup:members"],
            "dst": ["autogroup:internet:*"],
        },
    ],
    "groups": {"group:test": ["test@example.com", "opensource@frenck.dev"]},
    "tagOwners": {
        "tag:golink": ["group:test"],
    },
    "disableIPv4": True,
}


@pytest.mark.asyncio
async def test_policy_get(aresponses: ResponsesMockServer) -> None:
    """Test the get policy response handling."""
    aresponses.add(
        "api.tailscale.com",
        "/api/v2/tailnet/frenck/acl",
        "GET",
        aresponses.Response(
            status=200,
            headers={"Content-Type": "application/json"},
            text=json.dumps(test_policy_1),
        ),
    )

    async with aiohttp.ClientSession() as session:
        tailscale = Tailscale(tailnet="frenck", api_key="abc", session=session)
        ts_policy = await tailscale.policy()
        assert isinstance(ts_policy, Policy)
        assert ts_policy.acls[0].src[0] == "10.10.10.10/10"
        assert ts_policy.groups is not None
        if ts_policy.groups is None:
            return
        assert len(ts_policy.groups.get("group:test", [])) > 0
        assert ts_policy.groups["group:test"][0] == "test@example.com"

    aresponses.assert_plan_strictly_followed()
