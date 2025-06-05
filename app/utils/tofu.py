from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from flask import current_app
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app import db
from app.models.tofu import TrustedKey, TrustStatus


def calculate_key_fingerprint(public_key_pem: str) -> str:
    """Calculate SHA256 fingerprint of a X25519 public key"""
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(key, x25519.X25519PublicKey):
            msg = "Key is not an X25519 public key"
            current_app.logger.error(msg)
        key_der = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(key_der).hexdigest()
    except Exception as e:
        current_app.logger.exception("Failed to calculate key fingerprint")
        msg = "Invalid X25519 public key format"
        raise ValueError(msg) from e


def fix_invalid_enum_values() -> None:
    """Fix invalid enum values in the database by updating lowercase to uppercase"""
    try:
        current_app.logger.info("Attempting to fix invalid enum values in trusted_keys table")

        db.session.execute(
            text("UPDATE trusted_keys SET trust_status = 'TRUSTED' WHERE trust_status = 'trusted'"),
        )
        db.session.execute(
            text("UPDATE trusted_keys SET trust_status = 'REVOKED' WHERE trust_status = 'revoked'"),
        )
        db.session.execute(
            text("UPDATE trusted_keys SET trust_status = 'SUSPICIOUS' WHERE trust_status = 'suspicious'"),
        )

        db.session.commit()
        current_app.logger.info("Successfully fixed invalid enum values")

    except Exception:
        current_app.logger.exception("Failed to fix invalid enum values")
        try:
            db.session.rollback()
        except Exception:
            current_app.logger.exception("Failed to rollback after enum fix failure")
        raise


def verify_tofu_key(user_id: str, public_key_pem: str) -> tuple[bool, str, TrustedKey | None]:
    """Verify a public key using TOFU principles"""
    try:
        fingerprint = calculate_key_fingerprint(public_key_pem)

        trusted_key = None
        try:
            trusted_key = TrustedKey.query.filter_by(
                user_id=user_id,
                key_fingerprint=fingerprint,
            ).first()
        except (SQLAlchemyError, LookupError) as e:
            current_app.logger.warning(
                "Database error loading trusted key for user %s: %s (type: %s)",
                user_id,
                str(e),
                type(e).__name__,
            )

            try:
                current_app.logger.info("Attempting to fix invalid enum values...")
                fix_invalid_enum_values()
                current_app.logger.info("Database enum fix completed, retrying query...")

                # Create a fresh session for the retry
                db.session.expire_all()
                trusted_key = TrustedKey.query.filter_by(
                    user_id=user_id,
                    key_fingerprint=fingerprint,
                ).first()
                current_app.logger.info("Successfully retrieved trusted key after fix")

            except Exception:
                current_app.logger.exception("Failed to fix database enum values")
                return (
                    False,
                    "Database integrity error - please contact administrator",
                    None,
                )

        if trusted_key:
            current_app.logger.debug(
                "Found existing key for user %s with trust_status: %s (type: %s)",
                user_id,
                trusted_key.trust_status,
                type(trusted_key.trust_status).__name__,
            )

            if trusted_key.public_key == public_key_pem:
                if trusted_key.trust_status == TrustStatus.TRUSTED:
                    trusted_key.mark_verified()
                    db.session.commit()
                    return True, "Key verified successfully", trusted_key
                if trusted_key.trust_status == TrustStatus.REVOKED:
                    return False, "Key has been revoked", trusted_key
                return False, "Key is marked as suspicious", trusted_key

            current_app.logger.warning(
                "Setting trust_status to SUSPICIOUS for user %s due to key content mismatch. Previous status: %s",
                user_id,
                trusted_key.trust_status,
            )
            trusted_key.trust_status = TrustStatus.SUSPICIOUS
            db.session.commit()
            current_app.logger.warning(
                "Key content mismatch for user %s, fingerprint %s",
                user_id,
                fingerprint,
            )
            return False, "Key content has changed - possible security breach", trusted_key

        new_trusted_key = TrustedKey(user_id, fingerprint, public_key_pem)
        current_app.logger.debug(
            "Creating new trusted key for user %s with trust_status: %s (type: %s)",
            user_id,
            new_trusted_key.trust_status,
            type(new_trusted_key.trust_status).__name__,
        )
        db.session.add(new_trusted_key)
        db.session.commit()
        current_app.logger.info(
            "New key trusted for user %s, fingerprint %s",
            user_id,
            fingerprint,
        )

    except (ValueError, TypeError) as e:
        current_app.logger.exception("TOFU verification failed")
        return False, f"TOFU verification error: {e!s}", None
    else:
        return True, "Key trusted on first use", new_trusted_key


def revoke_user_key(user_id: str, key_fingerprint: str) -> bool:
    """Revoke a trusted key"""
    try:
        trusted_key = TrustedKey.query.filter_by(
            user_id=user_id,
            key_fingerprint=key_fingerprint,
        ).first()

        if trusted_key:
            current_app.logger.info(
                "Revoking key for user %s. Current status: %s, setting to: %s",
                user_id,
                trusted_key.trust_status,
                TrustStatus.REVOKED,
            )
            trusted_key.trust_status = TrustStatus.REVOKED
            db.session.commit()
            return True
    except Exception:
        current_app.logger.exception("Failed to revoke key")
        return False
    else:
        return False


def validate_trust_status_integrity() -> list[str]:
    """Check for any invalid enum values in the database and return issues found"""
    issues = []
    try:
        result = db.session.execute(
            text(
                (
                    "SELECT id, user_id, trust_status FROM trusted_keys "
                    "WHERE trust_status NOT IN ('TRUSTED', 'REVOKED', 'SUSPICIOUS')"
                ),
            ),
        ).fetchall()

        for row in result:
            issues.append(f"Invalid trust_status '{row.trust_status}' found for key ID {row.id} (user: {row.user_id})")
            current_app.logger.warning(
                "Found invalid trust_status '%s' for key ID %s (user: %s)",
                row.trust_status,
                row.id,
                row.user_id,
            )

        if issues:
            current_app.logger.error("Found %d invalid enum values in database", len(issues))

    except Exception:
        current_app.logger.exception("Failed to validate trust status integrity")
        issues.append("Failed to check database integrity")

    return issues
