"""JSON <-> Python conversion at the binding boundary (src/convert.rs).

jose-rs 0.10 turns on serde_json's ``arbitrary_precision`` and deserializes
``exp`` / ``iat`` / ``nbf`` from a ``RawValue``; these tests pin the numbers,
dict order and exception types that survive that.
"""

import pytest
from pygrindvakt import federation, jwt


def roundtrip(op_key, claims):
    return jwt.peek_claims_unverified(jwt.sign(op_key, claims))


def test_integers_floats_and_big_ints_roundtrip_as_native_numbers(op_key):
    out = roundtrip(op_key, {"big": 2**70, "neg": -5, "f": 1.5, "i": 7})
    assert out["big"] == 2**70 and type(out["big"]) is int
    assert out["neg"] == -5 and type(out["neg"]) is int
    assert out["i"] == 7 and type(out["i"]) is int
    assert out["f"] == 1.5 and type(out["f"]) is float


@pytest.mark.parametrize("claim", ["exp", "iat", "nbf"])
def test_numeric_date_claims_roundtrip(op_key, claim):
    assert roundtrip(op_key, {claim: 4102444800})[claim] == 4102444800
    assert roundtrip(op_key, {claim: 4102444800.5})[claim] == 4102444800.5


def test_nested_numbers_are_native(op_key):
    out = roundtrip(op_key, {"x": {"a": [1, 2.5, {"b": 3}]}})
    assert out["x"] == {"a": [1, 2.5, {"b": 3}]}


def test_wrong_shape_is_type_error():
    with pytest.raises(TypeError):
        federation.apply_policy(["not", "a", "dict"], {})
