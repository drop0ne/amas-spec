import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
sys.path.insert(0, str(REFERENCE))

from canonical_json import CanonicalJSONError, MAX_SAFE_INTEGER, MIN_SAFE_INTEGER, bytes_, dumps, sha256, validate


class CanonicalJSONTests(unittest.TestCase):
    def test_object_key_order_is_stable(self):
        first = {"z": 1, "a": {"b": 2, "a": 1}}
        second = {"a": {"a": 1, "b": 2}, "z": 1}
        self.assertEqual(dumps(first), dumps(second))
        self.assertEqual(sha256(first), sha256(second))
        self.assertEqual(dumps(first), '{"a":{"a":1,"b":2},"z":1}')

    def test_property_order_uses_utf16_code_units(self):
        # U+10000 encodes to D800 DC00 and therefore sorts before U+E000
        # under UTF-16 code-unit ordering despite its larger scalar value.
        value = {"\ue000": 1, "\U00010000": 2}
        self.assertEqual(dumps(value), '{"\U00010000":2,"\ue000":1}')

    def test_arrays_preserve_order(self):
        self.assertNotEqual(sha256([1, 2, 3]), sha256([3, 2, 1]))

    def test_boolean_and_integer_are_distinct(self):
        self.assertNotEqual(dumps(True), dumps(1))
        self.assertNotEqual(sha256({"v": True}), sha256({"v": 1}))

    def test_safe_integer_boundaries(self):
        self.assertEqual(dumps(MAX_SAFE_INTEGER), str(MAX_SAFE_INTEGER))
        self.assertEqual(dumps(MIN_SAFE_INTEGER), str(MIN_SAFE_INTEGER))
        for value in (MAX_SAFE_INTEGER + 1, MIN_SAFE_INTEGER - 1):
            with self.assertRaises(CanonicalJSONError):
                dumps({"value": value})

    def test_floats_are_forbidden_even_when_finite(self):
        for value in (0.0, 1.5, -2.0):
            with self.subTest(value=value):
                with self.assertRaises(CanonicalJSONError):
                    validate({"value": value})

    def test_nan_and_infinity_are_forbidden(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                with self.assertRaises(CanonicalJSONError):
                    dumps({"value": value})

    def test_surrogate_code_points_are_forbidden(self):
        with self.assertRaises(CanonicalJSONError):
            dumps({"value": "bad\ud800text"})
        with self.assertRaises(CanonicalJSONError):
            dumps({"bad\udfffkey": "x"})

    def test_non_string_object_key_is_forbidden(self):
        with self.assertRaises(CanonicalJSONError):
            dumps({1: "value"})

    def test_non_json_nested_type_is_forbidden(self):
        with self.assertRaises(CanonicalJSONError):
            dumps({"nested": {"bad": {1, 2}}})

    def test_unicode_is_utf8_not_ascii_escaped(self):
        value = {"text": "café Ω"}
        encoded = bytes_(value)
        self.assertIn("café Ω".encode("utf-8"), encoded)
        self.assertNotIn(b"\\u00e9", encoded)

    def test_control_character_escaping(self):
        self.assertEqual(dumps({"x": "\b\t\n\f\r\u0000"}), '{"x":"\\b\\t\\n\\f\\r\\u0000"}')

    def test_null_and_empty_structures_are_supported(self):
        self.assertEqual(dumps({"a": None, "b": [], "c": {}}), '{"a":null,"b":[],"c":{}}')

    def test_hash_shape_is_lowercase_sha256(self):
        digest = sha256({"x": 1})
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, digest.lower())
        int(digest, 16)


if __name__ == "__main__":
    unittest.main()
