#!/usr/bin/env python3
"""Regression for type-qualified handle constructor coverage."""
import unittest
from unittest.mock import patch
import check_c_binding_parity as parity


class HandleConstructorCoverage(unittest.TestCase):
    def test_static_constructor_preserves_type_qualification(self):
        with patch.object(parity, "_c_source", return_value="MediaFileTransferControlFfi::new();OtherHandle::new();"):
            covered = parity.subscription_coverage()
        self.assertIn("MediaFileTransferControlFfi::new", covered)
        self.assertIn("OtherHandle::new", covered)
        self.assertNotIn("new", covered)
        self.assertNotIn("MissingHandle::new", covered)

    def test_existing_instance_methods_remain_covered(self):
        with patch.object(parity, "_c_source", return_value="control.inner.cancel();control.inner.is_cancelled();"):
            covered = parity.subscription_coverage()
        self.assertIn("cancel", covered)
        self.assertIn("is_cancelled", covered)


if __name__ == "__main__":
    unittest.main()
