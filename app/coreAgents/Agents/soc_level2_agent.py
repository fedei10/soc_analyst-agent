from app.coreAgents.Agents.soc_level1_agent import load_prompt_template
from app.coreAgents.llm.groq import llm
from app.coreAgents.tools.wazuh.tool_registry import get_soc_l2_tools
from langchain.agents import create_agent

agent = create_agent(
    model=llm,
    tools=get_soc_l2_tools(),
    system_prompt=load_prompt_template("soc_level2_agent_system_prompt"),
)
