"""TLS trust policy: the operating system trust store by default, an explicit CA bundle when set.

Corporate TLS inspection re-signs tenant traffic with a private root certificate. That root is
normally already installed in the machine's own trust store by IT, but ``requests`` verifies against
certifi's bundle instead, so the handshake fails with CERTIFICATE_VERIFY_FAILED even though the
machine trusts the issuer. Verifying against the OS store fixes that without every operator
exporting a PEM by hand, and it keeps working when the proxy's root is rotated.

``truststore`` is optional. When it is missing the tool falls back to certifi and the existing
``[http] ca_bundle`` setting remains the supported way through TLS inspection.
"""
from __future__ import annotations

import logging
import ssl
import sys
from typing import Any

_INJECTED = False

# What the platform calls its trust store, so an operator knows where to look for the proxy root:
# certlm.msc on Windows, Keychain Access on macOS.
_SYSTEM_STORE_NAMES = {
    "win32": "Windows certificate store",
    "darwin": "macOS keychain",
}

TRUST_DESCRIPTIONS = {
    "ca_bundle": "CA bundle",
    "certifi": "certifi (default trust store)",
    "disabled": "VERIFICATION OFF -- traffic to the tenant is not authenticated",
}


def system_store_name() -> str:
    return _SYSTEM_STORE_NAMES.get(sys.platform, "system trust store")


def system_trust_available() -> bool:
    """Whether the OS trust store can be used for verification in this interpreter."""
    try:
        import truststore  # noqa: F401
    except ImportError:
        return False
    return True


def inject_system_trust() -> bool:
    """Make ssl.SSLContext verify against the OS trust store. True when active.

    This patches ``ssl.SSLContext`` for the whole process, so it has to run before anything builds
    a session. Calling it more than once is harmless.
    """
    global _INJECTED
    if _INJECTED:
        return True
    try:
        import truststore
    except ImportError:
        return False
    try:
        truststore.inject_into_ssl()
    except Exception:  # a platform whose trust store this build cannot read: fall back to certifi
        return False
    _INJECTED = True
    return True


def release_system_trust() -> bool:
    """Undo injection, so an explicit CA bundle genuinely constrains trust. True when it was active.

    While injected, certificates loaded through ``load_verify_locations`` (which is what
    ``verify=<path>`` becomes) are only an *additional* set of anchors: the OS store is consulted
    first and can authorise a certificate the configured bundle would have rejected. Windows tries
    the default chain engine before the custom one, and macOS calls
    ``SecTrustSetAnchorCertificatesOnly(trust, False)``. Either way a bundle would widen trust
    rather than pin it, so an explicit ``ca_bundle`` has to run un-injected.
    """
    global _INJECTED
    if not _INJECTED:
        return False
    try:
        import truststore
        truststore.extract_from_ssl()
    except Exception:
        return False
    _INJECTED = False
    return True


def apply_trust_policy(http_cfg: Any, log: logging.Logger | None = None) -> tuple[str | bool, str]:
    """Return ``(verify, source)`` for requests, activating OS trust when that is the source.

    Explicit settings always win: ``verify = false`` disables verification, then ``ca_bundle``
    selects a specific bundle, and only otherwise is the OS trust store used.
    """
    log = log or logging.getLogger("sia.trust")
    verify = http_cfg.tls_verify
    source = http_cfg.trust_source
    if source == "system":
        if inject_system_trust():
            log.debug("verifying TLS against the %s", system_store_name())
        else:
            source = "certifi"
            log.debug("truststore is not available; verifying TLS against certifi. Set [http] ca_bundle "
                      "if a TLS-inspecting proxy re-signs tenant traffic")
    elif release_system_trust():
        # Only reachable if something injected earlier in this process; keep the explicit setting authoritative.
        log.debug("released the %s so [http] %s stays authoritative", system_store_name(),
                  "ca_bundle" if source == "ca_bundle" else "verify")
    return verify, source


def describe_trust(http_cfg: Any, source: str | None = None) -> str:
    """One line naming the trust store in use, for preflight and doctor."""
    source = source or http_cfg.trust_source
    if source == "system" and not system_trust_available():
        source = "certifi"
    if source == "system":
        return system_store_name()
    if source == "ca_bundle":
        return f"{TRUST_DESCRIPTIONS['ca_bundle']} {http_cfg.ca_bundle}"
    return TRUST_DESCRIPTIONS.get(source, source)


def trust_context() -> ssl.SSLContext:
    """A verifying context built from the OS trust store, for callers that need one directly."""
    try:
        import truststore
    except ImportError:
        return ssl.create_default_context()
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
