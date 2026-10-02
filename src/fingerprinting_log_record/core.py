"""Compute a stable hash over a log record's level and message."""

import hashlib
import logging

# The record attributes that together form an event's identity for dedup.
# Level is included so that an INFO "disk full" and an ERROR "disk full"
# are not collapsed into one bucket by downstream consumers; they are
# semantically different events that happened to share wording.
_FINGERPRINT_FIELDS = ("levelname", "getMessage")


def _record_body(record: logging.LogRecord) -> str:
    """Build the canonical string hashed for the fingerprint.

    The level name is prefixed because the message alone is too coarse:
    identical text at different severities is a different event for triage.
    The message is obtained through ``getMessage`` so that %-style and
    brace-style formatting are both resolved before hashing, making the
    fingerprint a function of the rendered text rather than the raw
    format string and arguments.
    """
    level = record.levelname
    # ``getMessage`` resolves ``msg % args`` and the str.format adapter.
    # If formatting fails for any reason, fall back to the raw msg so we
    # never blow up the logging pipeline over a fingerprint.
    try:
        message = record.getMessage()
    except Exception:  # noqa: BLE001 - never raise from a logging filter
        message = record.getMessage.__self__.msg if hasattr(record.getMessage, "__self__") else str(record.msg)
    return f"{level}\x00{message}"


def fingerprint_record(record: logging.LogRecord) -> str:
    """Return a 16-character hex fingerprint identifying the record's event.

    The fingerprint is a truncated SHA-256 of the level name and the
    fully-rendered message, separated by a NUL byte. Truncation keeps the
    value short enough to be useful as a log field while retaining far more
    collision resistance than the problem demands; 16 hex chars = 64 bits.

    This function never raises: a logging filter that raises will silently
    drop records or break handlers, which is worse than a missing
    fingerprint. On any unexpected error it returns an empty string so
    downstream consumers can detect the absence.
    """
    try:
        body = _record_body(record)
        digest = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
        return digest[:16]
    except Exception:  # noqa: BLE001 - logging filters must not raise
        return ""


class FingerprintingFilter(logging.Filter):
    """Logging filter that attaches a stable ``fingerprint`` to each record.

    The fingerprint is written to ``record.fingerprint`` so formatters and
    downstream sinks can group identical events. Because it is a
    ``logging.Filter``, attaching it to a handler or logger is the standard
    ``addFilter`` call.

    Parameters
    ----------
    field_name:
        The attribute name set on the record. Defaults to ``"fingerprint"``.
        Override only if you have a pre-existing attribute of the same name.

    Design note
    -----------
    The filter always returns ``True``. Fingerprinting is observability, not
    gating; suppressing records here would surprise operators and break the
    contract of ``Filter`` in ways nothing in this library advertises.
    """

    def __init__(self, field_name: str = "fingerprint") -> None:
        super().__init__()
        self.field_name = field_name

    def filter(self, record: logging.LogRecord) -> bool:
        setattr(record, self.field_name, fingerprint_record(record))
        return True
