"""Asynchronous client for the Tailscale API."""
# pylint: disable=protected-access
import asyncio
import json
from typing import Dict

import aiohttp
import pytest
from aresponses import ResponsesMockServer

from tailscale import Tailscale
from tailscale.models import Policy

test_policy_1 = {
    "users": ["user@example.com"],
    "nodes": ["test"],
    "tagOwners": {
        "tag:golink" : "group:dev",
    },
    "routes": ["10.0.0.0/8"],
    "denyUnknown": True,
    "allowAll": False,
    "logActivity": True,
    "bypass": False,
}


@pytest.mark.asyncio
async def test_policy_get(aresponses: ResponsesMockServer):
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
        ts_policy = await tailscale.get_policy()
        assert isinstance(ts_policy, Policy)
        assert ts_policy.name == "test policy"
    
    aresponses.assert_plan_strictly_followed()


# @pytest.mark.asyncio
# async def test_policy_update(aresponses: ResponsesMockServer):
#     aresponses.add(
#         "api.tailscale.com",
#         "/api/v2/tailnet/frenck/acl",
#         "POST",
#         aresponses.Response(
#             status=200,
#             headers={"Content-Type": "application/json"},
#             text="{}",
#         ),
#         body_pattern="{\"tags\": [\"tag:testing\"]}",
#     )

#     async with aiohttp.ClientSession() as session:
#         tailscale = Tailscale(tailnet="frenck", api_key="abc", session=session)
#         await tailscale.tag_device("test", ["tag:testing"])  # nothing returned
#         assert (
#             aresponses.history[0].request.headers["Content-Type"] == "application/json"
#         )
#         posted = await aresponses.history[0].request.read()
#         assert posted == b'{"tags": ["tag:testing"]}'