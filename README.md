# fingerprinting-log-record

A `logging.Filter` that computes a stable SHA-256-based hash of a record's level and fully-rendered message, attaching it as `record.fingerprint` so downstream deduplication can group identical events.

## Usage

```python
import logging
from fingerprinting_log_record import FingerprintingFilter, fingerprint_record

handler = logging.StreamHandler()
handler.addFilter(FingerprintingFilter())
handler.setFormatter(logging.Formatter("%(fingerprint)s %(levelname)s %(message)s"))

logger = logging.getLogger("app")
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.error("disk %s", "full")   # emits: <16-hex> ERROR disk full
```

`fingerprint_record(record)` returns the 16-character hex string directly if you need it outside a filter.

## Why

When a service floods logs with the same event thousands of times, you want to collapse them by identity rather than by line. Raw line text is not enough: two loggers can emit the same message at different severities, and that distinction matters for triage. This library hashes the **level name** together with the **rendered message** (after `%`-style or `str.format` argument substitution) so identical events collapse while severity differences survive.

The trade-off: the fingerprint ignores logger name, timestamp, exception info, and stack context. It is a dedup key, not a unique record id. If you need to distinguish two "disk full" events from different components, pair the fingerprint with the logger name downstream.

## Edge case

If `record.getMessage()` raises (for example, a malformed format string or bad argument count), the filter does **not** propagate the exception. It falls back to hashing the raw `msg` and continues. This is deliberate: a logging filter that raises will silently drop records or break handlers, which is worse than a missing fingerprint. The cost is that two malformed records with the same raw template hash identically even if their arguments differ.
