"""Asynchronous client for the Tailscale API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator


class ClientSupports(BaseModel):
    """Object holding Tailscale device information."""

    hair_pinning: Optional[bool] = Field(..., alias="hairPinning")
    ipv6: Optional[bool]
    pcp: Optional[bool]
    pmp: Optional[bool]
    udp: Optional[bool]
    upnp: Optional[bool]


class ClientConnectivity(BaseModel):
    """Object holding Tailscale device information."""

    endpoints: List[str] = Field(default_factory=list)
    derp: str
    mapping_varies_by_dest_ip: Optional[bool] = Field(
        None, alias="mappingVariesByDestIP"
    )
    latency: Any
    client_supports: ClientSupports = Field(..., alias="clientSupports")


class Device(BaseModel):
    """Object holding Tailscale device information."""

    addresses: List[str]
    device_id: str = Field(..., alias="id")
    user: str
    name: str
    hostname: str
    client_version: str = Field(..., alias="clientVersion")
    update_available: bool = Field(..., alias="updateAvailable")
    os: str
    created: Optional[datetime]
    last_seen: Optional[datetime] = Field(..., alias="lastSeen")
    tags: Optional[List[str]]
    key_expiry_disabled: bool = Field(..., alias="keyExpiryDisabled")
    expires: Optional[datetime]
    authorized: bool
    is_external: bool = Field(..., alias="isExternal")
    machine_key: str = Field(..., alias="machineKey")
    node_key: str = Field(..., alias="nodeKey")
    blocks_incoming_connections: bool = Field(..., alias="blocksIncomingConnections")
    enabled_routes: List[str] = Field(alias="enabledRoutes", default_factory=list)
    advertised_routes: List[str] = Field(alias="advertisedRoutes", default_factory=list)
    client_connectivity: ClientConnectivity = Field(alias="clientConnectivity")

    @validator("created", pre=True)
    @classmethod
    def empty_as_none(cls, data: str | None) -> str | None:  # noqa: F841
        """Convert an emtpty string to None.

        Args:
            data: String to convert.

        Returns:
            String or none if string is empty.
        """
        if not data:
            return None
        return data


class Devices(BaseModel):
    """Object holding Tailscale device information."""

    devices: Dict[str, Device]

    @validator("devices", pre=True)
    @classmethod
    def convert_to_dict(
        cls, data: list[dict[str, Any]]  # noqa: F841
    ) -> dict[Any, dict[str, Any]]:
        """Convert list into dict, keyed by device id.

        Args:
            data: List of dicts to convert.

        Returns:
            dict: Converted list of dicts.
        """
        return {device["id"]: device for device in data}


class KeyAttributes(BaseModel):
    """Object describing Tailscale key capabilities."""

    reusable: bool = Field(default=False)
    ephemeral: bool = Field(default=False)
    preauthorized: bool = Field(default=True)
    tags: Optional[List[str]] = Field(default_factory=list)


class KeyCapabilities(BaseModel):
    """Object describing Tailscale key capabilities."""

    devices: Dict[str, KeyAttributes] = Field(default={"create": KeyAttributes()})


class AuthKeyRequest(BaseModel):
    """Object holding Tailscale API/Auth key information."""

    capabilities: KeyCapabilities
    expiry_seconds: int = Field(default=86400, alias="expirySeconds")


class AuthKey(BaseModel):
    """Object holding Tailscale API/Auth key information."""

    key_id: str = Field(..., alias="id")
    key: Optional[str]
    created: datetime
    expires: datetime
    revoked: Optional[datetime]
    capabilities: Optional[KeyCapabilities]  # api keys don't have capabilities


class AuthKeys(BaseModel):
    """Object holding Tailscale multiple Auth keys information."""

    keys: List[Dict[str, str]]
