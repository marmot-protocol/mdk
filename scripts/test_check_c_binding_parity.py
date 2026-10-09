#!/usr/bin/env python3
"""Regression for type-qualified handle constructor coverage."""
import unittest
import io
from contextlib import redirect_stderr
from unittest.mock import patch
import check_c_binding_parity as parity


class HandleConstructorCoverage(unittest.TestCase):
    def test_other_instance_constructor_cannot_cover_missing_handle(self):
        with (
            patch.object(parity, "uniffi_exports", return_value={"MissingHandle::new": "media.rs"}),
            patch.object(parity, "c_coverage", return_value=set()),
            patch.object(parity, "_c_source", return_value="other.new();OtherHandle::new();"),
            patch.object(parity, "DELIBERATELY_UNEXPORTED", {}),
            patch.object(parity.sys, "argv", ["check_c_binding_parity.py"]),
            redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(parity.main(), 1)
        self.assertIn("MissingHandle::new", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
