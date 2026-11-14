

import csv
import io
import re
from dataclasses import dataclass
from datetime import date

from .decision import Decision, Timer
from .errors import EngineError
from .hashing import canonical_json, hash_input

ALLOWED_PURPOSES = frozenset({"evaluation", "threshold_tuning", "bias_audit"})
REQUIRED_FIELDS = ("subject_id", "consent_given", "consent_date", "purpose", "image_file")
OPTIONAL_FIELDS = ("group", "consent_withdrawn")
ALL_FIELDS = frozenset(REQUIRED_FIELDS + OPTIONAL_FIELDS)

SUBJECT_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")        
GROUP_RE = re.compile(r"^[A-Za-z0-9 _/-]{1,40}$")
FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$") 
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

DEFAULT_GROUP = "undisclosed"
HIGH_SEVERITY_CODES = {"CON-MISSING", "CON-NOT-GRANTED", "CON-WITHDRAWN"}


@dataclass(frozen=True)
class ConsentRecord:
    subject_id: str
    consent_date: str
    purpose: str
    group: str
    image_file: str


def validate_consent_record(raw, today: date | None = None) -> ConsentRecord:
    """Return a normalized ConsentRecord or raise EngineError with a stable code."""
    today = today or date.today()

    if not isinstance(raw, dict) or not raw:
        raise EngineError("CON-MISSING", "no record supplied")

    unknown = set(raw) - ALL_FIELDS
    if unknown:  # names only; values are never echoed
        raise EngineError("CON-INVALID", f"unknown field count={len(unknown)}")

    # consent flag first: it is the gate
    if "consent_given" not in raw:
        raise EngineError("CON-MISSING", "field=consent_given")
    for name in REQUIRED_FIELDS:
        if name not in raw:
            raise EngineError("CON-INVALID", f"missing field={name}")

    if not isinstance(raw["consent_given"], bool):
        raise EngineError("CON-INVALID", "field=consent_given must be true/false")
    if raw["consent_given"] is False:
        raise EngineError("CON-NOT-GRANTED", "field=consent_given")

    withdrawn = raw.get("consent_withdrawn", False)
    if not isinstance(withdrawn, bool):
        raise EngineError("CON-INVALID", "field=consent_withdrawn must be true/false")
    if withdrawn:
        raise EngineError("CON-WITHDRAWN", "field=consent_withdrawn")

    subject_id = raw["subject_id"]
    if not isinstance(subject_id, str) or not SUBJECT_RE.match(subject_id):
        raise EngineError("CON-INVALID", "field=subject_id format")

    image_file = raw["image_file"]
    if not isinstance(image_file, str) or not FILE_RE.match(image_file):
        raise EngineError("CON-INVALID", "field=image_file format")

    consent_date = raw["consent_date"]
    if not isinstance(consent_date, str) or not DATE_RE.match(consent_date):
        raise EngineError("CON-DATE-INVALID", "field=consent_date format")
    try:
        parsed = date.fromisoformat(consent_date)
    except ValueError:
        raise EngineError("CON-DATE-INVALID", "field=consent_date not a real date")
    if parsed > today:
        raise EngineError("CON-DATE-INVALID", "field=consent_date in the future")

    purpose = raw["purpose"]
    if not isinstance(purpose, str) or purpose not in ALLOWED_PURPOSES:
        raise EngineError("CON-PURPOSE-INVALID", "field=purpose")

    group = raw.get("group", DEFAULT_GROUP)
    if group in (None, ""):
        group = DEFAULT_GROUP
    if not isinstance(group, str) or not GROUP_RE.match(group.strip()):
        raise EngineError("CON-INVALID", "field=group format")

    return ConsentRecord(
        subject_id=subject_id,
        consent_date=consent_date,
        purpose=purpose,
        group=group.strip().lower(),
        image_file=image_file,
    )


def _input_ref(raw) -> str:
    """Hash of the record (pseudonymous data only), safe even for odd input."""
    try:
        text = canonical_json(raw)
    except (TypeError, ValueError):
        text = repr(type(raw))
    return hash_input(text.encode("utf-8"))


def consent_decision(raw, config_hash: str, today: date | None = None):
    """Run the gate and return (Decision, ConsentRecord | None).

    Never raises for a business rejection: a rejection is a normal,
    auditable result with a named rule.
    """
    timer = Timer()
    ref = _input_ref(raw)
    try:
        record = validate_consent_record(raw, today)
    except EngineError as err:
        detail = f" [{err.detail}]" if err.detail else ""
        decision = Decision.create(
            stage="consent",
            status="rejected",
            outcome="CONSENT_REJECTED",
            severity="high" if err.code in HIGH_SEVERITY_CODES else "medium",
            rules_fired=[err.code],
            reasons=[f"{err.public_message}{detail}"],
            config_hash=config_hash,
            input_ref=ref,
            latency_ms=timer.ms(),
        )
        return decision, None

    decision = Decision.create(
        stage="consent",
        status="completed",
        outcome="CONSENT_VERIFIED",
        severity="info",
        reasons=[
            f"Consent granted and not withdrawn; purpose '{record.purpose}' is permitted; "
            f"consent date {record.consent_date} is valid."
        ],
        config_hash=config_hash,
        input_ref=ref,
        latency_ms=timer.ms(),
    )
    return decision, record


def parse_manifest(data: bytes, limits: dict) -> list:
    """Parse a CSV manifest into a list of raw row dicts (not yet consent-checked)."""
    if not isinstance(data, (bytes, bytearray)):
        raise EngineError("MAN-INVALID", "manifest must be bytes")
    if len(data) > limits["max_manifest_bytes"]:
        raise EngineError("MAN-TOO-LARGE", "bytes")
    try:
        text = bytes(data).decode("utf-8-sig")  
    except UnicodeDecodeError:
        raise EngineError("MAN-INVALID", "not valid UTF-8")

    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        headers = reader.fieldnames or []
        if not set(REQUIRED_FIELDS) <= set(headers) or not set(headers) <= ALL_FIELDS:
            raise EngineError("MAN-INVALID", "header columns do not match the schema")
        if len(headers) != len(set(headers)):
            raise EngineError("MAN-INVALID", "duplicate header columns")

        rows, seen_files = [], set()
        for number, row in enumerate(reader, start=2):  
            if len(rows) >= limits["max_manifest_rows"]:
                raise EngineError("MAN-TOO-LARGE", "rows")
            if None in row or any(v is None for v in row.values()):
                raise EngineError("MAN-INVALID", f"row={number} wrong column count")
            clean = {}
            for key, value in row.items():
                value = value.strip()
                if key in ("consent_given", "consent_withdrawn"):
                    if value == "":
                        continue  
                    lowered = value.lower()
                    clean[key] = True if lowered == "true" else False if lowered == "false" else value
                else:
                    clean[key] = value
            name = clean.get("image_file")
            if name in seen_files:
                raise EngineError("MAN-INVALID", f"row={number} duplicate image_file")
            seen_files.add(name)
            rows.append(clean)
    except csv.Error:
        raise EngineError("MAN-INVALID", "csv structure error")
    return rows


def evaluate_manifest(data: bytes, limits: dict, config_hash: str, today: date | None = None):
    """Parse and consent-check every row. Returns [(row_number, Decision, record|None)]."""
    results = []
    for index, raw in enumerate(parse_manifest(data, limits), start=2):
        decision, record = consent_decision(raw, config_hash, today)
        results.append((index, decision, record))
    return results