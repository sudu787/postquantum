"""Pick the post-quantum backend used by kex.py and auth.py.

liboqs-python (Open Quantum Safe) is preferred. If it is missing, or the
PQ_BACKEND environment variable is set to "pure", the pure-Python kyber-py
and dilithium-py packages are used instead. Those are FIPS 203/204
implementations meant for learning: they are slow and not constant-time.
"""
import os


def load_oqs():
    """Return the oqs module, or None if the pure-Python fallback should be used."""
    if os.environ.get("PQ_BACKEND", "").lower() == "pure":
        return None
    try:
        import oqs  # noqa: F401  (liboqs-python)
        return oqs
    except Exception:  # ImportError, or liboqs native library not found
        return None
