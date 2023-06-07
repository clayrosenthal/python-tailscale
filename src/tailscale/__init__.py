"""Asynchronous client for the Tailscale API."""
from .exceptions import (
    TailscaleAuthenticationError,
    TailscaleConnectionError,
    TailscaleError,
)
from .models import (
    AuthKey,
    AuthKeyRequest,
    AuthKeys,
    ClientConnectivity,
    ClientSupports,
    Device,
    Devices,
    KeyAttributes,
)
from .tailscale import Tailscale

__all__ = [
    "AuthKey",
    "AuthKeyRequest",
    "AuthKeys",
    "ClientConnectivity",
    "ClientSupports",
    "Device",
    "Devices",
    "KeyAttributes",
    "Tailscale",
    "TailscaleAuthenticationError",
    "TailscaleConnectionError",
    "TailscaleError",
]
