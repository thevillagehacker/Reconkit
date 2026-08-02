"""Safe validators registry (prove v2)."""

from __future__ import annotations

from typing import Any, Callable

from . import nuclei, sqli_boolean, ssrf_review, ssti, takeover, xss

ValidatorFn = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]

REGISTRY: dict[str, ValidatorFn] = {
    "xss_reflect": xss.validate,
    "ssti_math": ssti.validate,
    "nuclei_recheck": nuclei.validate,
    "takeover_fingerprint": takeover.validate,
    "ssrf_canary_review": ssrf_review.validate,
    "sqli_boolean": sqli_boolean.validate,
}


def get_validator(technique: str) -> ValidatorFn | None:
    return REGISTRY.get(technique)


def list_techniques() -> list[str]:
    return sorted(REGISTRY.keys())
