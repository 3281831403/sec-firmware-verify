"""Firmware manifest verification: executable specification (stubs only).

A device upgrades by downloading an image plus a JSON manifest that binds the
image hash, a monotonic version and the previous image's hash.  The verifier
must reject downgrades and same-version replays, forged or truncated
signatures, substituted images, and spliced hash chains.

Data shapes
-----------
A *manifest* is a dict::

    {
        "version": int,              # >= 1, strictly increasing per device
        "image_hash": str,           # 64 lowercase hex chars (SHA-256)
        "signature": str,            # 64 lowercase hex chars (HMAC-SHA256)
        "parent_hash": str | None,   # previous image hash, None for genesis
    }

An *update* passed to :func:`fw_batch` is::

    {"manifest": manifest, "image": bytes[, "min_version": int]}

A *batch config* is::

    {"key": bytes, "min_version": int}

All functions are deterministic, offline and standard-library only.  They
must not mutate their arguments and must not raise for ordinary verification
failures unless the docstring says otherwise.  Comparisons are exact: no
version, hash or signature matching has any tolerance (tolerance 0).
"""

import hashlib
import hmac
import json

CANONICAL_FIELDS = ("version", "image_hash", "parent_hash")
HASH_HEX_LEN = 64
MIN_TRUSTED_VERSION = 1

# Fixed-width sentinel used so a malformed candidate still goes through the
# single constant-time comparison instead of triggering an early return.
_BAD_SIGNATURE_HEX = "0" * HASH_HEX_LEN
_HASH_CHUNK_SIZE = 64 * 1024


def _is_int(value):
    """True only for genuine integers (``bool`` is explicitly excluded)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hex(value):
    """True when every character of ``value`` is a hexadecimal digit."""
    try:
        int(value, 16)
    except (TypeError, ValueError):
        return False
    return True


def _is_valid_hash_hex(value):
    """True for a 64-character hex string (case-insensitive input)."""
    return isinstance(value, str) and len(value) == HASH_HEX_LEN and _is_hex(value)


def parse_manifest(blob):
    """Parse and normalize a firmware manifest.

    ``blob`` is UTF-8 ``bytes``/``str`` containing exactly one JSON object.

    Return a new dict with:

      * ``version``: ``int`` (a decimal string is accepted and converted);
        it must be >= 1;
      * ``image_hash`` and ``signature``: lowercase 64-char hex strings;
      * ``parent_hash``: lowercase 64-char hex string, or ``None`` for a
        genesis manifest (both JSON ``null`` and ``""`` normalize to
        ``None``);
      * all other input keys preserved unchanged.

    Raise ``ValueError`` for malformed JSON, a non-object document, a missing
    required field, an unusable ``version``, or a hash/signature that is not a
    64-char hex string.  ``version`` is required: a missing version must be
    reported, never defaulted to 0, because 0 would let an old image claim to
    be a legal upgrade.
    """
    if isinstance(blob, str):
        raw = blob
    elif isinstance(blob, (bytes, bytearray)):
        raw = bytes(blob).decode("utf-8")
    else:
        raise ValueError("manifest blob must be str or bytes")

    try:
        document = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("malformed manifest JSON") from exc

    if not isinstance(document, dict):
        raise ValueError("manifest must be a JSON object")

    # Defect 1: a missing version is an error, never an implicit zero that an
    # old image could use to pose as a fresh upgrade.
    if "version" not in document:
        raise ValueError("missing required field: version")

    version = document["version"]
    if _is_int(version):
        normalized_version = version
    elif isinstance(version, str) and version.strip().lstrip("-").isdigit():
        normalized_version = int(version.strip())
    else:
        # bools, floats, None and non-decimal strings are unusable versions.
        raise ValueError("version must be an integer >= 1")
    if normalized_version < MIN_TRUSTED_VERSION:
        raise ValueError("version must be >= 1")

    for field in ("image_hash", "signature"):
        if field not in document:
            raise ValueError(f"missing required field: {field}")
        if not _is_valid_hash_hex(document[field]):
            raise ValueError(f"{field} must be a 64-char hex string")

    if "parent_hash" not in document:
        raise ValueError("missing required field: parent_hash")
    parent_hash = document["parent_hash"]
    if parent_hash is None or parent_hash == "":
        normalized_parent = None
    elif _is_valid_hash_hex(parent_hash):
        normalized_parent = parent_hash.lower()
    else:
        raise ValueError("parent_hash must be None, '' or a 64-char hex string")

    # Build a fresh dict so the caller's document is never mutated.
    normalized = dict(document)
    normalized["version"] = normalized_version
    normalized["image_hash"] = document["image_hash"].lower()
    normalized["signature"] = document["signature"].lower()
    normalized["parent_hash"] = normalized_parent
    return normalized


def hash_image(image):
    """Return the lowercase SHA-256 hex digest of ``image``.

    ``image`` is a bytes-like object.  Hash the complete byte stream in
    fixed-size chunks so memory use is independent of image length; the
    result must equal ``hashlib.sha256(image).hexdigest()`` for every input.
    The digest must be reproducible across processes and must never rely on
    Python's builtin ``hash()`` (which is salted per process and is not a
    cryptographic collision-resistant function).
    """
    # Defect 2: SHA-256 from hashlib, streamed in chunks -- reproducible,
    # collision-resistant, independent of PYTHONHASHSEED and image length.
    digest = hashlib.sha256()
    view = memoryview(image)
    for offset in range(0, len(view), _HASH_CHUNK_SIZE):
        digest.update(view[offset:offset + _HASH_CHUNK_SIZE])
    return digest.hexdigest()


def verify_signature(manifest, key, sig):
    """Verify an HMAC-SHA256 manifest signature in constant time.

    The signed bytes are::

        json.dumps({field: manifest[field] for field in CANONICAL_FIELDS},
                   sort_keys=True, separators=(",", ":")).encode("utf-8")

    so the signature covers ``version``, ``image_hash`` and ``parent_hash``
    but not ``signature`` itself.

    ``sig`` may be a 64-char hex ``str`` or the 32 raw digest ``bytes``.
    Normalize the candidate to a fixed-length hexadecimal value and compare
    it with ``hmac.compare_digest`` exactly once.  Do not use ``==``, and do
    not inspect the length first and return early: a truncated or otherwise
    malformed signature must still pass through the same single constant-time
    comparison and then return ``False``.  Missing manifest fields or wrong
    argument types also return ``False`` instead of raising.
    """
    try:
        # Defects 3 & 4: no "==", no length-based early return.  Every path
        # funnels into exactly one hmac.compare_digest call on equal-length
        # hex strings, so no length information leaks via control flow.
        payload = {field: manifest[field] for field in CANONICAL_FIELDS}
        signed = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        expected = hmac.new(key, signed, hashlib.sha256).hexdigest()

        if isinstance(sig, str) and _is_valid_hash_hex(sig):
            candidate = sig.lower()
        elif isinstance(sig, (bytes, bytearray)) and len(sig) == hashlib.sha256().digest_size:
            candidate = bytes(sig).hex()
        else:
            # Truncated/wrong-typed candidate: pad out to the fixed width and
            # let the single constant-time comparison reject it.
            candidate = _BAD_SIGNATURE_HEX

        return hmac.compare_digest(candidate, expected)
    except (TypeError, ValueError, KeyError, AttributeError):
        # Malformed manifest, bad key type, missing fields: verification
        # failure, never an exception.
        return False


def verify_chain(manifests):
    """Validate a parent-hash chain ordered oldest to newest.

    ``manifests[0]`` must be genesis: its ``parent_hash`` is ``None`` or
    ``""``.  For every ``i >= 1``, ``manifests[i]["parent_hash"]`` must equal
    ``manifests[i - 1]["image_hash"]`` (hex comparison is case-insensitive).

    Walk every link: checking only the first or last pair, or stopping at the
    first break, misses a break in the middle of the chain.  Return one string
    ``"index=<i>"`` per offending position, in ascending order; an intact
    chain returns ``[]``.  A first entry that is not genesis is reported as
    ``"index=0"``.
    """
    # Defect 5: walk the whole chain and collect every broken link instead of
    # checking a single pair, so a splice in the middle cannot slip through.
    problems = []
    if not manifests:
        return problems

    first_parent = manifests[0].get("parent_hash")
    if first_parent is not None and first_parent != "":
        problems.append("index=0")

    for index in range(1, len(manifests)):
        parent_hash = manifests[index].get("parent_hash")
        previous_image_hash = manifests[index - 1].get("image_hash")
        if (
            not isinstance(parent_hash, str)
            or not isinstance(previous_image_hash, str)
            or parent_hash.lower() != previous_image_hash.lower()
        ):
            problems.append(f"index={index}")
    return problems


def anti_rollback(version, min_version):
    """Return ``True`` only when ``version`` is strictly newer than the floor.

    ``version`` and ``min_version`` must be integers (``bool`` is not an
    integer here).  ``min_version`` is the trusted floor stored in device
    policy and must be >= 1.  A caller-supplied ``0`` or negative value is an
    untrusted bypass attempt and raises ``ValueError``: it must not silently
    disable rollback protection.

    Equal versions are replays, not progress, so they return ``False``; any
    older version also returns ``False``.  Only ``version > min_version`` is
    acceptable.
    """
    if not _is_int(min_version) or min_version < MIN_TRUSTED_VERSION:
        # Defect 7: an untrusted/zero/negative floor is rejected outright
        # instead of silently turning rollback protection off.
        raise ValueError("min_version must be a trusted integer >= 1")
    if not _is_int(version):
        raise ValueError("version must be an integer")

    # Defect 6: strictly greater -- an equal version is a replay, not progress.
    return version > min_version


def validate_manifest(manifest):
    """Return a list of problem codes; ``[]`` exactly when the manifest is valid.

    Required fields are ``version``, ``image_hash``, ``signature`` and
    ``parent_hash``; ``parent_hash`` may be ``None`` or ``""`` (genesis).
    Check, and emit applicable codes, in this order:

      * ``"manifest:not-dict"``;
      * ``"missing:<field>"`` for each missing required field;
      * ``"version:not-int"`` (a ``bool`` is not an int) and
        ``"version:out-of-range"`` (must be >= 1);
      * ``"image_hash:not-str"``, ``"image_hash:bad-length"`` (exactly 64
        characters) and ``"image_hash:not-hex"``;
      * ``"signature:not-str"``, ``"signature:bad-length"`` and
        ``"signature:not-hex"``;
      * ``"parent_hash:bad"`` when the value is neither ``None``/``""`` nor a
        64-char hex string.

    A truncated hash is invalid: checking only that the characters are hex is
    not enough.  This function checks structure only; it does not verify the
    HMAC.
    """
    problems = []
    if not isinstance(manifest, dict):
        return ["manifest:not-dict"]

    required = ("version", "image_hash", "signature", "parent_hash")
    for field in required:
        if field not in manifest:
            problems.append(f"missing:{field}")

    if "version" in manifest:
        if not _is_int(manifest["version"]):
            problems.append("version:not-int")
        elif manifest["version"] < MIN_TRUSTED_VERSION:
            problems.append("version:out-of-range")

    for field in ("image_hash", "signature"):
        if field not in manifest:
            continue
        value = manifest[field]
        prefix = field
        if not isinstance(value, str):
            problems.append(f"{prefix}:not-str")
            continue
        # Defect 9: enforce the exact digest length, so a truncated hash made
        # of valid hex characters is still rejected.
        if len(value) != HASH_HEX_LEN:
            problems.append(f"{prefix}:bad-length")
        if not _is_hex(value):
            problems.append(f"{prefix}:not-hex")

    if "parent_hash" in manifest:
        parent_hash = manifest["parent_hash"]
        if parent_hash is not None and parent_hash != "":
            if not _is_valid_hash_hex(parent_hash):
                problems.append("parent_hash:bad")

    return problems


def verify_image(manifest, image, key):
    """Verify one image against its manifest and return a result dict.

    The result shape is::

        {
            "ok": bool,             # hash_ok and signature_ok and version_ok
            "hash_ok": bool,        # hash_image(image) == image_hash
            "signature_ok": bool,   # verify_signature(manifest, key, ...)
            "version_ok": bool,     # version is an int >= 1
            "version": int | None,
            "image_hash": str | None,
            "errors": [str],        # stable codes, in check order
        }

    Check the image hash and the signature independently.  A valid signature
    must never mask a hash mismatch: if ``hash_ok`` is false then ``ok`` is
    false.  Conversely the hash is still compared when the signature is bad.
    Error codes are ``"manifest:invalid"`` for missing or ill-typed core
    fields, ``"image_hash:mismatch"``, ``"signature:invalid"`` and
    ``"version:invalid"``.  Malformed input produces a result dict with
    ``ok`` false; it does not raise.
    """
    result = {
        "ok": False,
        "hash_ok": False,
        "signature_ok": False,
        "version_ok": False,
        "version": None,
        "image_hash": None,
        "errors": [],
    }

    try:
        structural_problems = validate_manifest(manifest)
        if structural_problems:
            result["errors"].append("manifest:invalid")

        image_hash = manifest.get("image_hash") if isinstance(manifest, dict) else None
        if isinstance(image_hash, str):
            result["image_hash"] = image_hash
            # Defect 8: the hash is always computed and compared, even if the
            # signature check fails; a bad hash can never be masked.
            result["hash_ok"] = hmac.compare_digest(
                hash_image(image), image_hash.lower()
            )
        if not result["hash_ok"]:
            result["errors"].append("image_hash:mismatch")

        signature = manifest.get("signature") if isinstance(manifest, dict) else None
        result["signature_ok"] = verify_signature(manifest, key, signature)
        if not result["signature_ok"]:
            result["errors"].append("signature:invalid")

        version = manifest.get("version") if isinstance(manifest, dict) else None
        if _is_int(version) and version >= MIN_TRUSTED_VERSION:
            result["version_ok"] = True
            result["version"] = version
        else:
            result["errors"].append("version:invalid")

        result["ok"] = (
            result["hash_ok"]
            and result["signature_ok"]
            and result["version_ok"]
        )
    except (TypeError, ValueError, KeyError, AttributeError):
        # Any malformed input collapses into a failed result dict.
        result["ok"] = False
    return result


def _validate_trusted_floor(floor):
    """Shared guard for floors that originate in trusted policy."""
    if not _is_int(floor) or floor < MIN_TRUSTED_VERSION:
        raise ValueError("min_version must be a trusted integer >= 1")
    return floor


def fw_batch(updates, config):
    """Verify a list of independent firmware updates.

    ``config`` is ``{"key": bytes, "min_version": int}``; the floor comes from
    trusted device policy and must be >= 1.  Each update is
    ``{"manifest": dict, "image": bytes}`` and may override the floor for its
    own device with ``"min_version"`` (also >= 1).

    For each update, run :func:`verify_image`, then additionally require
    ``anti_rollback(version, effective_floor)``.  If that fails, set
    ``version_ok`` to ``False``, append ``"version:below-floor"`` and force
    ``ok`` to ``False``.  Updates are independent: neither the floor, nor a
    version or signature from one update, may leak into the next one.

    Return::

        {
            "ok": bool,               # every result is ok
            "results": [result, ...], # verify_image results, input order, with
                                      # the floor adjustment applied
            "failed": [index, ...],   # indices whose result is not ok
        }

    When an update passes the floor and :func:`verify_image` already returned
    ``ok``, its entry must compare equal to a direct :func:`verify_image`
    call (no extra keys, no rewritten values).  A malformed config floor
    raises ``ValueError``; a malformed per-update floor makes only that entry
    fail with ``"min_version:invalid"``.
    """
    config_floor = _validate_trusted_floor(config.get("min_version"))
    key = config.get("key")

    results = []
    failed = []

    for index, update in enumerate(updates):
        manifest = update.get("manifest")
        image = update.get("image")

        # Defect 10: derive the effective floor afresh for every update from
        # the trusted config value; no state is carried over from a previous
        # update's threshold.
        if "min_version" in update:
            floor = update["min_version"]
            if not _is_int(floor) or floor < MIN_TRUSTED_VERSION:
                result = verify_image(manifest, image, key)
                result["ok"] = False
                result["errors"].append("min_version:invalid")
                results.append(result)
                failed.append(index)
                continue
        else:
            floor = config_floor

        result = verify_image(manifest, image, key)

        version = result["version"]
        if version is not None:
            try:
                if not anti_rollback(version, floor):
                    result["version_ok"] = False
                    result["ok"] = False
                    result["errors"].append("version:below-floor")
            except ValueError:
                result["ok"] = False
                result["errors"].append("version:below-floor")
        else:
            result["ok"] = False

        if not result["ok"]:
            failed.append(index)
        results.append(result)

    return {"ok": not failed, "results": results, "failed": failed}
