"""Stable error codes for the security engine.

The API layer maps these codes to HTTP responses. The public message is
safe to show to any user; `detail` is for the audit log only and must
never contain secrets, biometric data, or file contents.
"""

ERROR_CATALOG = {
    # File / dataset validation
    "FILE-TYPE-INVALID": "The file type is not allowed.",
    "FILE-TOO-LARGE": "The file exceeds the maximum allowed size.",
    "FILE-DIMENSIONS-INVALID": "The image dimensions are outside the allowed range.",
    "FILE-CORRUPT": "The file could not be read as a valid image.",
    # Consent
    "CON-MISSING": "A valid consent record is required.",
    "CON-INVALID": "The consent record is incomplete or malformed.",
    "CON-NOT-GRANTED": "Consent has not been granted for this subject.",
    "CON-WITHDRAWN": "Consent has been withdrawn for this subject.",
    "CON-DATE-INVALID": "The consent date is invalid or in the future.",
    "CON-PURPOSE-INVALID": "The stated purpose is not permitted.",
    # Manifest
    "MAN-INVALID": "The manifest is malformed.",
    "MAN-TOO-LARGE": "The manifest exceeds the allowed size or row count.",
    # Embeddings
    "EMB-NO-FACE": "No face was detected in the image.",
    "EMB-MULTI-FACE": "More than one face was detected; exactly one is required.",
    "EMB-INVALID-VECTOR": "The embedding vector is invalid.",
    # Metrics
    "DATA-INSUFFICIENT": "Not enough data to compute this result reliably.",
    # Configuration
    "CFG-UNKNOWN-KEY": "That setting does not exist or cannot be changed.",
    "CFG-INVALID-TYPE": "The setting value has the wrong type.",
    "CFG-OUT-OF-RANGE": "The setting value is outside the permitted range.",
    "CFG-INCONSISTENT": "The settings are inconsistent with each other.",
    # Deletion
    "DEL-VERIFY-FAILED": "Deletion could not be verified.",
    # Fallback
    "ENG-INTERNAL": "An internal error occurred.",
}


class EngineError(Exception):
    """Raised by engine functions. Carries a stable code, never a stack trace to users."""

    def __init__(self, code: str, detail: str | None = None):
        if code not in ERROR_CATALOG:
            code = "ENG-INTERNAL"
        self.code = code
        self.public_message = ERROR_CATALOG[code]
        self.detail = detail  # audit-log only; must not contain sensitive data
        super().__init__(code)

    def to_dict(self) -> dict:
        """Safe representation for API responses (no detail, no traceback)."""
        return {"error_code": self.code, "message": self.public_message}