"""Cached loading for agent prompt templates."""

from functools import lru_cache
from pathlib import Path

import yaml


PROMPT_TEMPLATES_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "prompt_templates.yaml"
)


@lru_cache(maxsize=32)
def load_prompt_template(template_name: str) -> str:
    with PROMPT_TEMPLATES_PATH.open("r", encoding="utf-8") as handle:
        templates = yaml.safe_load(handle) or {}

    template = templates.get(template_name)
    if template is None:
        raise KeyError(
            f"Prompt template '{template_name}' was not found in "
            f"{PROMPT_TEMPLATES_PATH}"
        )
    if not isinstance(template, str):
        raise TypeError(
            f"Prompt template '{template_name}' in "
            f"{PROMPT_TEMPLATES_PATH} must be a string"
        )
    return template
