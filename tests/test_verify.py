"""Executable contract for firmware manifest verification.

These tests are immutable: they are the acceptance criteria for the eight
stubs in ``fw/verify.py``.  Only the standard library and pytest are used.
"""

import hashlib
import hmac
import json

import pytest

from fw.verify import (
    anti_rollback,
    fw_batch,
    hash_image,
    parse_manifest,
    validate_manifest,
    verify_chain,
    verify_image,
    verify_signature,
)

KEY = b"vendor-root-key-v1"
IMAGE = b"firmware-image-0001"


def canonical_bytes(manifest):
    """Bytes covered by the manifest HMAC (test-side reference signer)."""
    payload = {
        field: manifest[field] for field in ("version", "image_hash", "parent_hash")
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(manifest, key=KEY):
    """Reference HMAC-SHA256 signature for a manifest."""
    return hmac.new(key, canonical_bytes(manifest), hashlib.sha256).hexdigest()


def make_manifest(version=2, image=IMAGE, parent_hash=None, key=KEY):
    """Build a correctly signed manifest for ``image``."""
    manifest = {
        "version": version,
        "image_hash": hashlib.sha256(image).hexdigest(),
        "parent_hash": parent_hash,
    }
    manifest["signature"] = sign(manifest, key)
    return manifest


def make_chain(length=3):
    """Build an intact, correctly signed chain ordered oldest to newest."""
    manifests = []
    parent_hash = None
    for index in range(length):
        image = f"firmware-image-{index:04d}".encode("ascii")
        manifest = make_manifest(
            version=index + 1, image=image, parent_hash=parent_hash
        )
        parent_hash = manifest["image_hash"]
        manifests.append(manifest)
    return manifests


def test_parse_manifest_missing_version_is_rejected():
    blob = json.dumps(
        {
            "image_hash": hashlib.sha256(IMAGE).hexdigest(),
            "signature": "a" * 64,
            "parent_hash": None,
        }
    ).encode("utf-8")
    with pytest.raises(ValueError):
        parse_manifest(blob)


def test_hash_image_matches_sha256_and_is_deterministic():
    image = b"\x00\xfffirmware-block" * 4096
    expected = hashlib.sha256(image).hexdigest()
    assert hash_image(image) == expected
    assert hash_image(image) == expected
    assert isinstance(hash_image(image), str)


def test_verify_signature_uses_constant_time_compare(monkeypatch):
    manifest = make_manifest()
    seen = []
    real_compare = hmac.compare_digest

    def spy(left, right):
        seen.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    assert verify_signature(manifest, KEY, manifest["signature"]) is True
    assert len(seen) == 1
    assert len(seen[0][0]) == len(seen[0][1])


def test_verify_signature_wrong_length_does_not_return_early(monkeypatch):
    manifest = make_manifest()
    seen = []
    real_compare = hmac.compare_digest

    def spy(left, right):
        seen.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    assert verify_signature(manifest, KEY, "deadbeef") is False
    assert len(seen) == 1
    assert len(seen[0][0]) == len(seen[0][1])


def test_verify_chain_reports_middle_break():
    manifests = make_chain(4)
    manifests[2]["parent_hash"] = "0" * 64
    assert verify_chain(manifests) == ["index=2"]


def test_anti_rollback_rejects_equal_version_replay():
    assert anti_rollback(5, 5) is False


def test_anti_rollback_rejects_untrusted_zero_floor():
    with pytest.raises(ValueError):
        anti_rollback(10, 0)
    with pytest.raises(ValueError):
        anti_rollback(10, -3)


def test_verify_image_rejects_hash_mismatch_despite_valid_signature():
    manifest = make_manifest(version=3, image=b"genuine-image")
    result = verify_image(manifest, b"tampered-image", KEY)
    assert result["signature_ok"] is True
    assert result["hash_ok"] is False
    assert result["ok"] is False
    assert "image_hash:mismatch" in result["errors"]


def test_validate_manifest_rejects_truncated_image_hash():
    manifest = make_manifest()
    manifest["image_hash"] = manifest["image_hash"][:16]
    problems = validate_manifest(manifest)
    assert "image_hash:bad-length" in problems


def test_fw_batch_does_not_reuse_previous_threshold():
    config = {"key": KEY, "min_version": 5}
    first = {
        "manifest": make_manifest(version=9, image=b"first-image"),
        "image": b"first-image",
    }
    second = {
        "manifest": make_manifest(version=6, image=b"second-image"),
        "image": b"second-image",
    }
    result = fw_batch([first, second], config)
    assert result["ok"] is True
    assert result["failed"] == []
    assert result["results"][1]["version_ok"] is True


def test_valid_signature_accepted():
    manifest = make_manifest(version=7, image=b"signed-image")
    assert verify_signature(manifest, KEY, manifest["signature"]) is True
    forged = sign(manifest, key=b"attacker-key")
    assert verify_signature(manifest, KEY, forged) is False
    result = verify_image(manifest, b"signed-image", KEY)
    assert result["ok"] is True
    assert result["signature_ok"] is True
    assert result["errors"] == []


def test_tampered_image_rejected_in_batch():
    config = {"key": KEY, "min_version": 1}
    good = {
        "manifest": make_manifest(version=2, image=b"good-image"),
        "image": b"good-image",
    }
    bad = {
        "manifest": make_manifest(version=2, image=b"good-image"),
        "image": b"evil-image",
    }
    result = fw_batch([good, bad], config)
    assert result["results"][0]["ok"] is True
    assert result["results"][1]["ok"] is False
    assert result["ok"] is False
    assert result["failed"] == [1]


def test_version_rollback_rejected():
    assert anti_rollback(4, 5) is False
    assert anti_rollback(5, 5) is False
    assert anti_rollback(6, 5) is True


def test_chain_intact_passes_and_broken_fails():
    intact = make_chain(3)
    assert verify_chain(intact) == []
    broken = make_chain(3)
    broken[1]["parent_hash"] = "f" * 64
    assert verify_chain(broken) == ["index=1"]


def test_batch_results_match_individual_verification():
    config = {"key": KEY, "min_version": 5}
    updates = [
        {
            "manifest": make_manifest(version=6, image=b"batch-one"),
            "image": b"batch-one",
        },
        {
            "manifest": make_manifest(version=10, image=b"batch-two"),
            "image": b"batch-two",
        },
    ]
    result = fw_batch(updates, config)
    assert result["ok"] is True
    assert result["failed"] == []
    assert result["results"][0] == verify_image(
        updates[0]["manifest"], b"batch-one", KEY
    )
    assert result["results"][1] == verify_image(
        updates[1]["manifest"], b"batch-two", KEY
    )
