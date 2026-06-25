from dataclasses import dataclass
from typing import ClassVar

from cryptography.hazmat.primitives import hashes


@dataclass(frozen=True)
class AlgorithmPolicy:
    default_digest: str = "sha256"
    allowed_digests: ClassVar[set[str]] = {"sha256", "sha384", "sha512"}
    disallowed_digests: ClassVar[set[str]] = {"md5", "sha1"}

    def normalize_digest(self, digest: str | None = None) -> str:
        candidate = (digest or self.default_digest).lower().replace("-", "")
        if candidate in self.disallowed_digests:
            raise ValueError(f"Digest algorithm is disallowed: {candidate}")
        if candidate not in self.allowed_digests:
            raise ValueError(f"Digest algorithm is not allowed: {candidate}")
        return candidate

    def display_digest(self, digest: str | None = None) -> str:
        normalized = self.normalize_digest(digest)
        return normalized.upper().replace("SHA", "SHA-")

    def pyhanko_digest(self, digest: str | None = None) -> str:
        return self.normalize_digest(digest)

    def cryptography_hash(self, digest: str | None = None) -> hashes.HashAlgorithm:
        normalized = self.normalize_digest(digest)
        if normalized == "sha256":
            return hashes.SHA256()
        if normalized == "sha384":
            return hashes.SHA384()
        if normalized == "sha512":
            return hashes.SHA512()
        raise ValueError(f"Unsupported digest algorithm: {normalized}")


ALGORITHM_POLICY = AlgorithmPolicy()
