"""STEALTHWALL FastAPI middleware package (PyPI target, FastAPI only).

Django and Flask are explicitly NOT supported (plan Section 5).
"""

from .features import extract_features, feature_vector_envelope, FEATURE_KEYS

__all__ = ["extract_features", "feature_vector_envelope", "FEATURE_KEYS"]
