# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Malformed closed multisigs, as Bitcoin Core reports them.

Issue btclib-org/btclib-wallet#476. Core is the release
`integration-bitcoind.yml` pins. Its miniscript parser refuses a multisig
outside its own context before it reads a key, and reads each key of one
in its own context up to the next comma, counting no bracket.

A multisig descriptor function that ends in ")" is read by Core's
descriptor parser instead, each argument up to a "," or an unpaired
closing bracket (issue btclib-org/bip32-descriptors#53).
"""

import pytest
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from bip32_descriptors.descriptors import parse
from bip32_descriptors.descriptors.miniscript import P2WSH, TAPSCRIPT
from bip32_descriptors.descriptors.miniscript import parse as parse_miniscript
from tests.descriptors import P2WSH_FAULT, TR_LEAF_FAULT
from tests.secret_free import assert_secret_free

_KEY = PrvKeyData(1).pub.sec.hex()
_X_ONLY = _KEY[2:]
_KEY_FAULT = "^invalid key expression$"


@pytest.mark.parametrize(
    "descriptor,message",
    [
        (
            f"tr({_X_ONLY},and_v(v:pk({_X_ONLY}),multi(1,[dead]]{_X_ONLY},{_X_ONLY})))",
            TR_LEAF_FAULT,
        ),
        (
            f"tr({_X_ONLY},and_v(v:pk({_X_ONLY}),multi(1,{_X_ONLY},{_X_ONLY})))",
            TR_LEAF_FAULT,
        ),
        (
            f"tr({_X_ONLY},{{pk({_X_ONLY}),and_v(v:pk({_X_ONLY}),multi(1,nope))}})",
            TR_LEAF_FAULT,
        ),
        (
            f"wsh(and_v(v:pk({_KEY}),multi_a(1,[dead]]{_KEY},{_KEY})))",
            P2WSH_FAULT,
        ),
        (
            f"sh(wsh(and_v(v:pk({_KEY}),multi_a(1,[dead]]{_KEY},{_KEY}))))",
            P2WSH_FAULT,
        ),
        (f"wsh(and_v(v:pk({_KEY}),multi_a(1,{_KEY},{_KEY})))", P2WSH_FAULT),
    ],
)
def test_a_multisig_outside_its_context_reads_no_key(
    descriptor: str, message: str
) -> None:
    """Core names its fallback for the context, not a key of the multisig."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor,message",
    [
        (f"tr({_X_ONLY},and_v(v:multi_a(1,{_X_ONLY}{{),pk({_X_ONLY})))", _KEY_FAULT),
        (
            f"tr({_X_ONLY},and_v(v:multi_a(1,{_X_ONLY},{_X_ONLY}{{),pk({_X_ONLY})))",
            _KEY_FAULT,
        ),
        (
            f"tr({_X_ONLY},and_v(v:multi_a(1,[dead]]{_X_ONLY},{_X_ONLY}{{),pk({_X_ONLY})))",
            r"^more than one '\]' in a single key expression$",
        ),
        (f"wsh(and_v(v:multi(1,{_KEY}{{),pk({_KEY})))", _KEY_FAULT),
    ],
)
def test_a_bracket_in_a_multisig_key_is_the_key_fault(
    descriptor: str, message: str
) -> None:
    """Core reads the key a stray bracket sits in before the structure."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor",
    [
        f"tr({_X_ONLY},and_v(v:multi_a(x,{_X_ONLY}{{),pk({_X_ONLY})))",
        f"tr({_X_ONLY},and_v(v:multi_a(1,,{_X_ONLY}{{),pk({_X_ONLY})))",
    ],
)
def test_no_key_past_a_bad_threshold_or_an_empty_key_is_read(descriptor: str) -> None:
    """Core stops before the bracketed key, so no key fault is named.

    Core then names its fallback for the leaf, and so does parse.
    """
    with pytest.raises(BTClibValueError, match=TR_LEAF_FAULT):
        parse(descriptor)


@pytest.mark.parametrize(
    "expression,context,message",
    [
        (f"multi(1,[dead]]{_X_ONLY})", TAPSCRIPT, "^multi.. is not allowed in a"),
        (f"multi_a(1,[dead]]{_KEY})", P2WSH, "^multi_a.. is only allowed in a"),
    ],
)
def test_the_standalone_parser_names_the_context(
    expression: str, context: str, message: str
) -> None:
    """The language parser keeps its own diagnostic, read before any key."""
    with pytest.raises(BTClibValueError, match=message):
        parse_miniscript(expression, context)


_K2 = PrvKeyData(2).pub.sec.hex()
_X2 = _K2[2:]
_WIF = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"


@pytest.mark.parametrize(
    "descriptor,name",
    [
        # Core: Multi: expected ',', got ')'
        (f"tr({_X_ONLY},multi_a(1,{_X_ONLY})())", "multi_a"),
        (f"tr({_X_ONLY},sortedmulti_a(1,{_X_ONLY})())", "sortedmulti_a"),
        (f"tr({_X_ONLY},{{pk({_X_ONLY}),multi_a(1,{_X_ONLY})()}})", "multi_a"),
        (f"tr({_X_ONLY},{{multi_a(1,{_X_ONLY},{_X2})(),pk({_X_ONLY})}})", "multi_a"),
        (f"wsh(multi(1,{_KEY})())", "multi"),
        (f"wsh(sortedmulti(1,{_KEY})())", "sortedmulti"),
        (f"sh(wsh(multi(1,{_KEY},{_K2})(,{_KEY})))", "multi"),
        (f"sh(sortedmulti(1,{_KEY})(x))", "sortedmulti"),
        (f"multi(1,{_KEY})()", "multi"),
        # before the threshold is compared with the keys
        (f"wsh(multi(2,{_KEY})())", "multi"),
        (f"tr({_X_ONLY},multi_a(2,{_X_ONLY})())", "multi_a"),
        # Core: Multi: expected ',', got '}'
        (f"tr({_X_ONLY},multi_a(1,{_X_ONLY}}}(,pk({_X_ONLY})))", "multi_a"),
        (f"wsh(multi(1,{_KEY}}}{{))", "multi"),
    ],
)
def test_a_bracket_after_a_multisig_key_is_the_multisig_fault(
    descriptor: str, name: str
) -> None:
    """Core reads the text up to the multisig's last ")" as its arguments."""
    message = rf"^{name}\(\): expected ',' after a key, got a closing bracket$"
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor",
    [
        "wsh(multi(1,zz)())",
        f"tr({_X_ONLY},multi_a(1,{_X_ONLY},zz)())",
    ],
)
def test_a_multisig_key_is_read_before_the_bracket_after_it(descriptor: str) -> None:
    """Core: Multi: key 'zz' is not valid."""
    with pytest.raises(BTClibValueError, match=_KEY_FAULT):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor",
    [
        f"sh(multi(1,{_KEY}),{_KEY}())",
        f"wsh(multi(1,{_KEY}),{_KEY}())",
    ],
)
def test_text_after_a_closed_multisig_is_not_its_arguments(descriptor: str) -> None:
    """Core cuts the multisig at the "," after it, and names no fault."""
    with pytest.raises(BTClibValueError, match="^unbalanced brackets$"):
        parse(descriptor)


def test_a_bracket_after_a_multisig_key_echoes_no_key() -> None:
    """The refusal leaves out the text, which holds a private key."""
    message = r"^multi\(\): expected ',' after a key, got a closing bracket$"
    with pytest.raises(BTClibValueError, match=message) as e:
        parse(f"wsh(multi(1,{_WIF})({_WIF}))")
    assert_secret_free(e.value, [_WIF])
