from functools import lru_cache
from pathlib import Path

import yaml

from app.coreAgents.llm.groq import llm
from langchain.agents import create_agent









#prompt path 
PROMPT_TEMPLATES_PATH = Path(__file__).resolve().parents[1] / "config" / "prompt_templates.yaml"

@lru_cache(maxsize=32)
def load_prompt_template(template_name: str) -> str:
    with PROMPT_TEMPLATES_PATH.open("r", encoding="utf-8") as handle:
        templates = yaml.safe_load(handle) or {}

    template = templates.get(template_name)

    if template is None:
        raise KeyError(
            f"Prompt template '{template_name}' was not found in {PROMPT_TEMPLATES_PATH}"
        )

    if not isinstance(template, str):
        raise TypeError(
            f"Prompt template '{template_name}' in {PROMPT_TEMPLATES_PATH} must be a string"
        )

    return template

agent = create_agent(
    model=llm,
    tools=[],
    system_prompt=load_prompt_template("soc_level1_agent_system_prompt")
)