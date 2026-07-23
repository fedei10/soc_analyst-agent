from app.coreAgents.Agents.soc_level1_agent import load_prompt_template
from app.coreAgents.llm.groq import llm
from app.coreAgents.tools.wazuh.tool_registry import get_soc_l3_tools
from langchain.agents import create_agent

# Active response is intentionally absent from the agent process.
agent = create_agent(
    model=llm,
    tools=get_soc_l3_tools(),
    system_prompt=load_prompt_template("soc_level3_agent_system_prompt"),
)
