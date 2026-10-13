"""Identifier-pattern guard and in-memory HMAC-SHA256 audit trail.

The pattern guard is a supplementary safeguard, not a PHI de-identification
method or a guarantee of HIPAA Safe Harbor compliance.
"""
import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

PHI_PATTERNS = [
    re.compile(r"\b(?:MRN)[:#\s-]*\d{4,10}\b", re.IGNORECASE),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b(?:DOB|Date of Birth)[:\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", re.IGNORECASE),
    re.compile(r"\b(?:Patient\s+Name|Patient)[:\s]+[A-Z][a-z]+\s+[A-Z][a-z]+\b", re.IGNORECASE),
    re.compile(r"\b(?:John\s+Doe|Jane\s+Smith|Alice\s+Johnson)\b", re.IGNORECASE),
]


class SecurityException(Exception):
    """Raised when an input matches a sensitive-identifier pattern."""


class ResourceLimitExceededException(Exception):
    """Raised when computational parameters exceed safety bounds."""


def assert_no_phi(text: str) -> None:
    if not text:
        return
    for pattern in PHI_PATTERNS:
        if pattern.search(str(text)):
            raise SecurityException("Potential sensitive identifier detected; use synthetic or de-identified input.")


class PHIGuard:
    @staticmethod
    def assert_no_phi(text: str) -> None:
        assert_no_phi(text)

    @staticmethod
    def redact_phi(text: str) -> str:
        res = str(text)
        for pattern in PHI_PATTERNS:
            res = pattern.sub("[REDACTED_IDENTIFIER]", res)
        return res


class AuditTrail:
    """In-memory chained HMAC audit records; not persistent or immutable storage."""

    GENESIS_HASH = "GENESIS_BLOCK_0000000000000000"
    SIGNED_FIELDS = ("audit_id", "timestamp", "actor", "actor_tier", "event_type", "payload_hash", "prev_hash")

    def __init__(self, secret_key: Optional[str] = None):
        resolved_key = secret_key or os.getenv("AUDIT_SECRET_KEY")
        if resolved_key:
            self.secret_key = resolved_key.encode("utf-8")
        else:
            self.secret_key = secrets.token_bytes(32)
            warnings.warn(
                "AUDIT_SECRET_KEY not set; generated an ephemeral random key. "
                "Audit integrity cannot be checked across restarts.",
                RuntimeWarning,
                stacklevel=2,
            )
        self.logs: List[Dict[str, Any]] = []

    def _sign(self, entry: Dict[str, Any]) -> str:
        signed_message = "|".join(str(entry[field]) for field in self.SIGNED_FIELDS)
        return hmac.new(self.secret_key, signed_message.encode("utf-8"), hashlib.sha256).hexdigest()

    def log(self, actor: str, actor_tier: str, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        payload_str = json.dumps(details, sort_keys=True)
        assert_no_phi(payload_str)
        for label in (actor, actor_tier, event_type):
            assert_no_phi(label)
        entry = {
            "audit_id": f"AUDIT-{int(time.time() * 1000)}-{len(self.logs) + 1}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "actor_tier": actor_tier,
            "event_type": event_type,
            "payload_hash": hashlib.sha256(payload_str.encode("utf-8")).hexdigest(),
            "prev_hash": self.logs[-1]["current_hash"] if self.logs else self.GENESIS_HASH,
        }
        entry["current_hash"] = self._sign(entry)
        self.logs.append(entry)
        return copy.deepcopy(entry)

    def verify_integrity(self) -> bool:
        previous = self.GENESIS_HASH
        for entry in self.logs:
            try:
                if entry["prev_hash"] != previous:
                    return False
                expected = self._sign(entry)
                if not hmac.compare_digest(expected, entry["current_hash"]):
                    return False
                previous = entry["current_hash"]
            except (KeyError, TypeError, ValueError):
                return False
        return True

    def get_trail(self) -> List[Dict[str, Any]]:
        return copy.deepcopy(self.logs)


GLOBAL_AUDIT = AuditTrail()


class AuditLogger:
    @staticmethod
    def log(actor: str, actor_tier: str, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        return GLOBAL_AUDIT.log(actor, actor_tier, event_type, details)

    @staticmethod
    def get_trail() -> List[Dict[str, Any]]:
        return GLOBAL_AUDIT.get_trail()

    @staticmethod
    def verify_integrity() -> bool:
        return GLOBAL_AUDIT.verify_integrity()


class ActionExecutor:
    @staticmethod
    def execute_with_audit(actor: str, actor_tier: str, action_type: str, fn, *args, **kwargs):
        result = fn(*args, **kwargs)
        AuditLogger.log(actor, actor_tier, action_type, {"status": "SUCCESS"})
        return result
