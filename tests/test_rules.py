from __future__ import annotations

from drop_vet import rules


def test_luhn() -> None:
    assert rules.luhn("4111111111111111")
    assert not rules.luhn("4111111111111112")


def test_decode_text_by_bom_and_nul() -> None:
    assert rules.decode_text("SSN 123-45-6789".encode("utf-16")) == ("SSN 123-45-6789", True)
    assert rules.decode_text("café".encode("utf-32"))[0] == "café"
    assert rules.decode_text(b"abc\x00def") == ("", False)
    assert rules.decode_text("naïve".encode("latin-1")) == ("naïve", True)


def test_pii_kinds() -> None:
    assert rules.pii_kinds("SSN 123-45-6789") == ["ssn"]
    assert rules.pii_kinds("SSN 000-12-3456") == []
    assert rules.pii_kinds("card 4111 1111 1111 1111 exp") == ["card_number"]
    assert rules.pii_kinds("order 4111 1111 1111 1112") == []
    assert rules.pii_kinds("Routing number: 021000021") == ["account_number"]
    assert rules.pii_kinds("attached is my W-2") == ["tax_form"]
    assert rules.pii_kinds("the fence repair is booked") == []


def test_secret_kinds() -> None:
    assert rules.secret_kinds("key AKIA" + "ABCDEFGHIJKLMNOP") == ["aws"]
    assert rules.secret_kinds("password = " + "hunter2hunter2xx") == ["labeled"]
    assert rules.secret_kinds("just a sentence about passwords") == []


def test_tier() -> None:
    assert rules.tier(["ssn"], ["image_not_text_scanned"]) == "sensitive"
    assert rules.tier([], ["no_text_layer"]) == "unverified"
    assert rules.tier([], []) == "normal"


def test_category_for_text() -> None:
    assert rules.category_for_text(".py") == "code"
    assert rules.category_for_text(".csv") == "data"
    assert rules.category_for_text(".md") == "text"
