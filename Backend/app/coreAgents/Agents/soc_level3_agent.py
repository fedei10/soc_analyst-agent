from app.coreAgents.llm.model_pool import get_agent_middleware, get_agent_model
from app.coreAgents.tools.python_functions.yaml_loader import load_prompt_template
from app.coreAgents.tools.wazuh.tool_registry import get_soc_l3_tools
from langchain.agents import create_agent

# Active response is intentionally absent from the agent process.
agent = create_agent(
    model=get_agent_model("l3"),
    tools=get_soc_l3_tools(),
    system_prompt=load_prompt_template("soc_level3_agent_system_prompt"),
    middleware=get_agent_middleware("l3"),
)
