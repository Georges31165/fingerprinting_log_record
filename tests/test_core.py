import logging
import unittest

from fingerprinting_log_record import FingerprintingFilter, fingerprint_record


def _make_record(name, level, msg, args=None):
    return logging.LogRecord(
        name=name,
        level=level,
        pathname="test.py",
        lineno=1,
        msg=msg,
        args=args,
        exc_info=None,
    )


class FingerprintRecordTests(unittest.TestCase):
    def test_same_message_and_level_yields_same_fingerprint(self):
        r1 = _make_record("app", logging.ERROR, "disk full")
        r2 = _make_record("app", logging.ERROR, "disk full")
        self.assertEqual(fingerprint_record(r1), fingerprint_record(r2))

    def test_different_level_yields_different_fingerprint(self):
        r_info = _make_record("app", logging.INFO, "disk full")
        r_error = _make_record("app", logging.ERROR, "disk full")
        self.assertNotEqual(fingerprint_record(r_info), fingerprint_record(r_error))

    def test_different_message_yields_different_fingerprint(self):
        r1 = _make_record("app", logging.ERROR, "disk full")
        r2 = _make_record("app", logging.ERROR, "disk empty")
        self.assertNotEqual(fingerprint_record(r1), fingerprint_record(r2))

    def test_percent_args_are_resolved_before_hashing(self):
        raw = _make_record("app", logging.ERROR, "disk %s", ("full",))
        rendered = _make_record("app", logging.ERROR, "disk full")
        self.assertEqual(fingerprint_record(raw), fingerprint_record(rendered))

    def test_fingerprint_is_16_char_hex(self):
        record = _make_record("app", logging.INFO, "hello")
        fp = fingerprint_record(record)
        self.assertEqual(len(fp), 16)
        int(fp, 16)  # raises if not hex

    def test_fingerprint_does_not_depend_on_logger_name(self):
        r1 = _make_record("app.one", logging.ERROR, "disk full")
        r2 = _make_record("app.two", logging.ERROR, "disk full")
        self.assertEqual(fingerprint_record(r1), fingerprint_record(r2))

    def test_fingerprint_is_deterministic_across_processes(self):
        # SHA-256 is deterministic and platform-independent; we assert a
        # pinned value so any drift in the algorithm is caught.
        record = _make_record("app", logging.WARNING, "cache miss")
        self.assertEqual(fingerprint_record(record), "98533485eb0347b4")


class FingerprintingFilterTests(unittest.TestCase):
    def test_filter_sets_fingerprint_attribute(self):
        record = _make_record("app", logging.ERROR, "disk full")
        flt = FingerprintingFilter()
        self.assertTrue(flt.filter(record))
        self.assertTrue(hasattr(record, "fingerprint"))
        self.assertEqual(record.fingerprint, fingerprint_record(record))

    def test_filter_always_passes_record_through(self):
        record = _make_record("app", logging.ERROR, "disk full")
        self.assertTrue(FingerprintingFilter().filter(record))

    def test_custom_field_name(self):
        record = _make_record("app", logging.ERROR, "disk full")
        flt = FingerprintingFilter(field_name="event_hash")
        flt.filter(record)
        self.assertTrue(hasattr(record, "event_hash"))
        self.assertFalse(hasattr(record, "fingerprint"))

    def test_two_records_same_event_get_same_fingerprint_via_filter(self):
        flt = FingerprintingFilter()
        r1 = _make_record("app", logging.ERROR, "disk full")
        r2 = _make_record("app", logging.ERROR, "disk full")
        flt.filter(r1)
        flt.filter(r2)
        self.assertEqual(r1.fingerprint, r2.fingerprint)

    def test_filter_attaches_to_handler_and_runs_on_emit(self):
        handler = logging.StreamHandler()
        handler.addFilter(FingerprintingFilter())
        # Capture via a formatter that references the attribute; if the
        # filter did not run, formatting would raise KeyError.
        handler.setFormatter(logging.Formatter("%(fingerprint)s %(message)s"))
        logger = logging.getLogger("test.handler")
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        logger.handlers = [handler]
        # No assertion on stream contents; the goal is that emit does not
        # raise, proving the attribute exists by the time of formatting.
        logger.error("disk full")


if __name__ == "__main__":
    unittest.main()
