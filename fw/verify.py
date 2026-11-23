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
import re

CANONICAL_FIELDS = ("version", "image_hash", "parent_hash")
HASH_HEX_LEN = 64
MIN_TRUSTED_VERSION = 1

REQUIRED_MANIFEST_FIELDS = ("version", "image_hash", "signature", "parent_hash")

_HEX_CHARS = frozenset("0123456789abcdef")
_DIGEST_LEN = 32  # SHA-256 / HMAC-SHA256 raw digest length
_CHUNK_SIZE = 64 * 1024
_DECIMAL_INT = re.compile(r"[+-]?[0-9]+")


def _is_hex64(value):
    """Return True when ``value`` is a 64-character hex string (any case)."""
    return (
        isinstance(value, str)
        and len(value) == HASH_HEX_LEN
        and all(char in _HEX_CHARS for char in value.lower())
    )


def _normalize_hash(value, field):
    """Return the lowercase form of a 64-char hex string or raise ValueError."""
    if not isinstance(value, str):
        raise ValueError("%s must be a string" % field)
    if len(value) != HASH_HEX_LEN:
        raise ValueError("%s must be %d hex characters" % (field, HASH_HEX_LEN))
    if not all(char in _HEX_CHARS for char in value.lower()):
        raise ValueError("%s must be hexadecimal" % field)
    return value.lower()


def _coerce_version(value):
    """Return a trusted integer version from an int or decimal string."""
    if isinstance(value, bool):
        raise ValueError("version must be an integer, not bool")
    if isinstance(value, int):
        version = value
    elif isinstance(value, str):
        token = value.strip()
        if not token.isascii() or _DECIMAL_INT.fullmatch(token) is None:
            raise ValueError("version must be a decimal integer")
        version = int(token, 10)
    else:
        raise ValueError("version must be an integer")
    if version < MIN_TRUSTED_VERSION:
        raise ValueError("version must be >= %d" % MIN_TRUSTED_VERSION)
    return version


def _normalize_candidate_signature(sig):
    """Reduce a candidate signature to a fixed-width raw digest.

    A 64-char hex string or 32 raw bytes both become 32 raw bytes.  Every
    other input (truncated, malformed, wrong type) becomes zero-padded bytes
    of the same fixed width so the constant-time comparison is still executed
    exactly once and never leaks the candidate's length.
    """
    raw = b""
    if isinstance(sig, str):
        token = sig.strip()
        try:
            raw = bytes.fromhex(token)
        except ValueError:
            raw = b""
    elif isinstance(sig, (bytes, bytearray, memoryview)):
        raw = bytes(sig)
    # Anything that is not exactly one digest is treated as an empty candidate
    # and padded to the fixed width below; truncating a longer value could make
    # a wrong signature compare equal.
    if len(raw) != _DIGEST_LEN:
        raw = b""
    return (raw + b"\x00" * _DIGEST_LEN)[:_DIGEST_LEN]


def _canonical_payload(manifest):
    """Return the bytes covered by the manifest HMAC."""
    payload = {field: manifest[field] for field in CANONICAL_FIELDS}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


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
    if isinstance(blob, (bytes, bytearray, memoryview)):
        try:
            text = bytes(blob).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("manifest is not valid UTF-8") from exc
    elif isinstance(blob, str):
        text = blob
    else:
        raise ValueError("manifest must be bytes or str")

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("manifest is not valid JSON") from exc

    if not isinstance(data, dict):
        raise ValueError("manifest must be a JSON object")

    for field in REQUIRED_MANIFEST_FIELDS:
        if field not in data:
            raise ValueError("manifest is missing required field: %s" % field)

    # ``version`` is mandatory and never defaulted: a missing or unusable
    # version must fail rather than masquerade as a legal upgrade.
    version = _coerce_version(data["version"])
    image_hash = _normalize_hash(data["image_hash"], "image_hash")
    signature = _normalize_hash(data["signature"], "signature")

    parent_hash = data["parent_hash"]
    if parent_hash is None or parent_hash == "":
        parent_hash = None
    else:
        parent_hash = _normalize_hash(parent_hash, "parent_hash")

    result = dict(data)
    result["version"] = version
    result["image_hash"] = image_hash
    result["signature"] = signature
    result["parent_hash"] = parent_hash
    return result


def hash_image(image):
    """Return the lowercase SHA-256 hex digest of ``image``.

    ``image`` is a bytes-like object.  Hash the complete byte stream in
    fixed-size chunks so memory use is independent of image length; the
    result must equal ``hashlib.sha256(image).hexdigest()`` for every input.
    The digest must be reproducible across processes and must never rely on
    Python's builtin ``hash()`` (which is salted per process and is not a
    cryptographic collision-resistant function).
    """
    try:
        view = memoryview(image)
    except TypeError as exc:
        raise TypeError("image must be a bytes-like object") from exc
    if view.ndim != 1 or view.itemsize != 1:
        view = view.cast("B")

    digest = hashlib.sha256()
    for offset in range(0, len(view), _CHUNK_SIZE):
        digest.update(view[offset:offset + _CHUNK_SIZE])
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
    # A missing core field makes the manifest un-signable: never accept a
    # signature computed over a *different* (shorter) payload.
    usable = isinstance(manifest, dict) and all(
        field in manifest for field in CANONICAL_FIELDS
    )
    expected = b"\x00" * _DIGEST_LEN
    if usable:
        try:
            expected = hmac.new(
                key, _canonical_payload(manifest), hashlib.sha256
            ).digest()
        except (KeyError, TypeError, ValueError, AttributeError):
            # Unusable manifest/key: fall through to the single constant-time
            # comparison below so the failure path has the same shape.
            usable = False
            expected = b"\x00" * _DIGEST_LEN

    candidate = _normalize_candidate_signature(sig)
    matched = hmac.compare_digest(expected, candidate)
    return bool(matched and usable)


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
    if not manifests:
        return []

    problems = []
    first = manifests[0]
    first_parent = first.get("parent_hash") if isinstance(first, dict) else None
    if first_parent is not None and first_parent != "":
        problems.append("index=0")

    # Recurse through every link; never stop at the first break.
    for index in range(1, len(manifests)):
        current = manifests[index]
        previous = manifests[index - 1]
        parent_hash = (
            current.get("parent_hash") if isinstance(current, dict) else None
        )
        previous_hash = (
            previous.get("image_hash") if isinstance(previous, dict) else None
        )
        if (
            not isinstance(parent_hash, str)
            or not isinstance(previous_hash, str)
            or parent_hash.lower() != previous_hash.lower()
        ):
            problems.append("index=%d" % index)
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
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError("version must be an integer, not bool")
    if isinstance(min_version, bool) or not isinstance(min_version, int):
        raise ValueError("min_version must be an integer, not bool")
    if min_version < MIN_TRUSTED_VERSION:
        raise ValueError(
            "min_version must be >= %d (untrusted floor)" % MIN_TRUSTED_VERSION
        )
    # Equal versions are replays and are rejected: only strict progress counts.
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
    if not isinstance(manifest, dict):
        return ["manifest:not-dict"]

    problems = []
    for field in REQUIRED_MANIFEST_FIELDS:
        if field not in manifest:
            problems.append("missing:%s" % field)

    if "version" in manifest:
        version = manifest["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            problems.append("version:not-int")
        elif version < MIN_TRUSTED_VERSION:
            problems.append("version:out-of-range")

    for field in ("image_hash", "signature"):
        if field not in manifest:
            continue
        value = manifest[field]
        if not isinstance(value, str):
            problems.append("%s:not-str" % field)
            continue
        # Length and character-set checks are independent: a truncated value
        # and a non-hex value are both reported when both apply.
        if len(value) != HASH_HEX_LEN:
            problems.append("%s:bad-length" % field)
        if not all(char in _HEX_CHARS for char in value.lower()):
            problems.append("%s:not-hex" % field)

    if "parent_hash" in manifest:
        parent_hash = manifest["parent_hash"]
        if not (
            parent_hash is None
            or parent_hash == ""
            or _is_hex64(parent_hash)
        ):
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
    if not isinstance(manifest, dict):
        result["errors"].append("manifest:invalid")
        return result

    has_version = "version" in manifest
    has_image_hash = "image_hash" in manifest
    has_signature = "signature" in manifest
    version = manifest.get("version")
    image_hash = manifest.get("image_hash")
    signature = manifest.get("signature")

    version_is_int = isinstance(version, int) and not isinstance(version, bool)
    core_ok = (
        has_version
        and has_image_hash
        and has_signature
        and version_is_int
        and isinstance(image_hash, str)
        and isinstance(signature, str)
    )

    if version_is_int:
        result["version"] = version
    if isinstance(image_hash, str):
        result["image_hash"] = image_hash

    # Hash and signature are checked independently; a valid signature never
    # masks a substituted image, and a bad signature never skips the hashing.
    try:
        actual_hash = hash_image(image)
    except (TypeError, ValueError):
        actual_hash = None
    hash_ok = False
    if actual_hash is not None and isinstance(image_hash, str):
        try:
            hash_ok = hmac.compare_digest(
                actual_hash.encode("ascii"), image_hash.lower().encode("utf-8")
            )
        except UnicodeEncodeError:
            # Undecodable text cannot be a valid digest; report, never raise.
            hash_ok = False

    try:
        signature_ok = verify_signature(manifest, key, signature)
    except Exception:  # pragma: no cover - defensive, verify_signature is total
        signature_ok = False

    version_ok = version_is_int and version >= MIN_TRUSTED_VERSION

    result["hash_ok"] = hash_ok
    result["signature_ok"] = signature_ok
    result["version_ok"] = version_ok
    result["ok"] = bool(core_ok and hash_ok and signature_ok and version_ok)

    if not core_ok:
        result["errors"].append("manifest:invalid")
    if isinstance(image_hash, str) and not hash_ok:
        result["errors"].append("image_hash:mismatch")
    if isinstance(signature, str) and not signature_ok:
        result["errors"].append("signature:invalid")
    if version_is_int and not version_ok:
        result["errors"].append("version:invalid")

    return result


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
    if not isinstance(config, dict):
        raise ValueError("config must be a dict")
    key = config.get("key")
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise ValueError("config key must be bytes")
    floor = config.get("min_version")
    if isinstance(floor, bool) or not isinstance(floor, int):
        raise ValueError("config min_version must be an integer")
    if floor < MIN_TRUSTED_VERSION:
        raise ValueError(
            "config min_version must be >= %d" % MIN_TRUSTED_VERSION
        )
    key = bytes(key)

    results = []
    failed = []
    for index, update in enumerate(updates):
        if not isinstance(update, dict):
            manifest = None
            image = None
            has_override = False
            override = None
        else:
            manifest = update.get("manifest")
            image = update.get("image")
            has_override = "min_version" in update
            override = update.get("min_version")

        result = verify_image(manifest, image, key)

        # The floor is recomputed for every update from the trusted config (or
        # this update's own override).  It is never carried over from the
        # previous iteration.
        if has_override:
            if (
                isinstance(override, bool)
                or not isinstance(override, int)
                or override < MIN_TRUSTED_VERSION
            ):
                result["version_ok"] = False
                result["ok"] = False
                result["errors"].append("min_version:invalid")
                results.append(result)
                failed.append(index)
                continue
            effective_floor = override
        else:
            effective_floor = floor

        version = result["version"]
        floor_ok = False
        if isinstance(version, int) and not isinstance(version, bool):
            try:
                floor_ok = anti_rollback(version, effective_floor)
            except ValueError:
                floor_ok = False

        if not floor_ok:
            result["version_ok"] = False
            result["ok"] = False
            result["errors"].append("version:below-floor")

        results.append(result)
        if not result["ok"]:
            failed.append(index)

    return {
        "ok": not failed,
        "results": results,
        "failed": failed,
    }
