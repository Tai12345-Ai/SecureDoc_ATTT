from dataclasses import dataclass
from typing import ClassVar

from cryptography.hazmat.primitives import hashes


@dataclass(frozen=True)
class AlgorithmPolicy:
    """
    Digest algorithm policy for SecureDoc.

    - Default: SHA-256
    - PAdES-compatible: SHA-256, SHA-384, SHA-512
    - Experimental (SHA-3): SHA3-256, SHA3-384, SHA3-512
      SHA-3 is available for canonical payload / advanced digest demo only.
      SHA-3 is NOT enabled for PAdES signing by default because pyHanko
      and most PDF validators do not support SHA-3 in PAdES signatures.
    - Disallowed: MD5, SHA-1
    """

    default_digest: str = "sha256"

    PADES_COMPATIBLE_DIGESTS: ClassVar[set[str]] = {"sha256", "sha384", "sha512"}
    EXPERIMENTAL_DIGESTS: ClassVar[set[str]] = {"sha3_256", "sha3_384", "sha3_512"}
    allowed_digests: ClassVar[set[str]] = PADES_COMPATIBLE_DIGESTS | EXPERIMENTAL_DIGESTS
    disallowed_digests: ClassVar[set[str]] = {"md5", "sha1"}

    # ── Display names ────────────────────────────────────────────────────
    _DISPLAY_MAP: ClassVar[dict[str, str]] = {
        "sha256": "SHA-256",
        "sha384": "SHA-384",
        "sha512": "SHA-512",
        "sha3_256": "SHA3-256",
        "sha3_384": "SHA3-384",
        "sha3_512": "SHA3-512",
    }

    # ── Normalization helpers ────────────────────────────────────────────

    def normalize_digest(self, digest: str | None = None) -> str:
        """Normalize a digest name to internal canonical form.

        Accepts flexible input: "sha-256", "SHA256", "sha3-256", "SHA3_256", etc.
        Returns one of: sha256, sha384, sha512, sha3_256, sha3_384, sha3_512.
        """
        candidate = (digest or self.default_digest).lower().strip()
        # Normalize separators: sha-256 -> sha256, sha3-256 -> sha3_256
        # First handle sha3 variants specifically
        candidate = candidate.replace(" ", "")
        # sha-3-256, sha-3_256 -> sha3_256
        candidate = candidate.replace("sha-3-", "sha3_").replace("sha-3_", "sha3_")
        # sha3-256 -> sha3_256
        candidate = candidate.replace("sha3-", "sha3_")
        # sha-256 -> sha256 (but not sha3_256 -> sha3256)
        if not candidate.startswith("sha3_"):
            candidate = candidate.replace("-", "").replace("_", "")

        if candidate in self.disallowed_digests:
            raise ValueError(f"Digest algorithm is disallowed: {candidate}")
        if candidate not in self.allowed_digests:
            raise ValueError(
                f"Digest algorithm is not allowed: {candidate}. "
                f"Allowed: {', '.join(sorted(self.allowed_digests))}"
            )
        return candidate

    def display_digest(self, digest: str | None = None) -> str:
        """Return human-readable display name (e.g. SHA-256, SHA3-256)."""
        normalized = self.normalize_digest(digest)
        return self._DISPLAY_MAP.get(normalized, normalized.upper())

    def pyhanko_digest(self, digest: str | None = None) -> str:
        """Return the digest name for pyHanko (only PAdES-compatible)."""
        normalized = self.normalize_digest(digest)
        if normalized not in self.PADES_COMPATIBLE_DIGESTS:
            raise ValueError(
                f"Digest {self.display_digest(normalized)} is experimental and not "
                f"enabled for PAdES signing. Use SHA-256/SHA-384/SHA-512 for PAdES."
            )
        return normalized

    def cryptography_hash(self, digest: str | None = None) -> hashes.HashAlgorithm:
        """Return a cryptography HashAlgorithm instance."""
        normalized = self.normalize_digest(digest)
        _hash_map: dict[str, hashes.HashAlgorithm] = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
            "sha3_256": hashes.SHA3_256(),
            "sha3_384": hashes.SHA3_384(),
            "sha3_512": hashes.SHA3_512(),
        }
        result = _hash_map.get(normalized)
        if result is None:
            raise ValueError(f"Unsupported digest algorithm: {normalized}")
        return result

    def is_pades_compatible(self, digest: str | None = None) -> bool:
        """Check if digest is usable for PAdES/PDF signing."""
        try:
            normalized = self.normalize_digest(digest)
        except ValueError:
            return False
        return normalized in self.PADES_COMPATIBLE_DIGESTS

    def is_experimental(self, digest: str | None = None) -> bool:
        """Check if digest is experimental (SHA-3)."""
        try:
            normalized = self.normalize_digest(digest)
        except ValueError:
            return False
        return normalized in self.EXPERIMENTAL_DIGESTS

    def digest_capabilities(self) -> dict:
        """Return a summary of available digest algorithms and their status."""
        return {
            "default": self.default_digest,
            "default_display": self.display_digest(self.default_digest),
            "pades_compatible": sorted(self.PADES_COMPATIBLE_DIGESTS),
            "pades_compatible_display": [
                self.display_digest(d) for d in sorted(self.PADES_COMPATIBLE_DIGESTS)
            ],
            "experimental": sorted(self.EXPERIMENTAL_DIGESTS),
            "experimental_display": [
                self.display_digest(d) for d in sorted(self.EXPERIMENTAL_DIGESTS)
            ],
            "disallowed": sorted(self.disallowed_digests),
            "note": (
                "SHA-3 digests are available for canonical payload demo and advanced "
                "research. They are NOT enabled for PAdES/PDF signing because most PDF "
                "validators do not support SHA-3 in CMS/PAdES signatures."
            ),
        }


ALGORITHM_POLICY = AlgorithmPolicy()
